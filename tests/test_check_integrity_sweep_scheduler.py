"""Unit tests for check_integrity_sweep_scheduler.py verification script."""

import importlib.util
import os

import pytest

SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "check_integrity_sweep_scheduler.py",
)
spec = importlib.util.spec_from_file_location("check_mod", SCRIPT)
check_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_mod)


class TestRunChecks:
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
        assert len(result) >= 70, f"Expected >= 70 checks, got {len(result)}"

    def test_all_checks_pass(self):
        result = check_mod.run_checks()
        failing = [c for c in result if not c["pass"]]
        assert not failing, f"Failing checks: {failing}"


class TestFileChecks:
    def test_implementation_file(self):
        checks = check_mod.run_checks()
        assert next(c for c in checks if c["check"] == "file: implementation")["pass"]

    def test_spec_file(self):
        checks = check_mod.run_checks()
        assert next(c for c in checks if c["check"] == "file: spec contract")["pass"]

    def test_trajectory_file(self):
        checks = check_mod.run_checks()
        assert next(c for c in checks if c["check"] == "file: trajectory artifact")["pass"]


class TestTypeChecks:
    TYPES = [
        "pub enum Trend",
        "pub struct EvidenceTrajectory",
        "pub enum PolicyBand",
        "pub enum SweepDepth",
        "pub struct SweepScheduleDecision",
        "pub struct SweepSchedulerConfig",
        "pub struct IntegritySweepScheduler",
    ]

    @pytest.mark.parametrize("ty", TYPES)
    def test_type_found(self, ty):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == f"type: {ty}")
        assert check["pass"], f"Type not found: {ty}"


class TestEventCodes:
    CODES = ["EVD-SWEEP-001", "EVD-SWEEP-002", "EVD-SWEEP-003", "EVD-SWEEP-004"]

    @pytest.mark.parametrize("code", CODES)
    def test_event_code_found(self, code):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == f"event_code: {code}")
        assert check["pass"]


class TestInvariants:
    INVARIANTS = [
        "INV-SWEEP-ADAPTIVE",
        "INV-SWEEP-HYSTERESIS",
        "INV-SWEEP-DETERMINISTIC",
        "INV-SWEEP-BOUNDED",
    ]

    @pytest.mark.parametrize("inv", INVARIANTS)
    def test_invariant_found(self, inv):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == f"invariant: {inv}")
        assert check["pass"]


class TestUnitTestCount:
    def test_count_passes(self):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == "unit test count")
        assert check["pass"]


class TestSelfTest:
    def test_self_test_passes(self):
        assert check_mod.self_test()


class TestCheckHelper:
    def test_pass_true(self):
        result = check_mod._check("t", True, "ok")
        assert result["pass"] is True

    def test_pass_false(self):
        result = check_mod._check("t", False)
        assert result["detail"] == "NOT FOUND"
