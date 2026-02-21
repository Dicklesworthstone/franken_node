"""Unit tests for scripts/check_compat_corpus_gate.py (bd-28sz: compatibility corpus gate)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_compat_corpus_gate",
    ROOT / "scripts" / "check_compat_corpus_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Test: run_all structure
# ---------------------------------------------------------------------------

class TestRunAllStructure(unittest.TestCase):
    def test_run_all_returns_dict(self):
        result = mod.run_all()
        self.assertIsInstance(result, dict)

    def test_run_all_has_required_keys(self):
        result = mod.run_all()
        for key in ["bead_id", "title", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_bead_id(self):
        self.assertEqual(mod.run_all()["bead_id"], "bd-28sz")

    def test_section(self):
        self.assertEqual(mod.run_all()["section"], "13")

    def test_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS")

    def test_total_equals_passed_plus_failed(self):
        result = mod.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])

    def test_checks_is_list(self):
        result = mod.run_all()
        self.assertIsInstance(result["checks"], list)

    def test_check_entry_structure(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)


# ---------------------------------------------------------------------------
# Test: self_test
# ---------------------------------------------------------------------------

class TestSelfTest(unittest.TestCase):
    def test_self_test_returns_bool(self):
        result = mod.self_test()
        self.assertIsInstance(result, bool)

    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


# ---------------------------------------------------------------------------
# Test: validate_corpus_result
# ---------------------------------------------------------------------------

class TestValidateCorpusResult(unittest.TestCase):
    def _make_result(self, **overrides):
        base = {
            "run_id": "run-001",
            "timestamp": "2026-02-20T12:00:00Z",
            "total_tests": 1000,
            "passed_tests": 960,
            "failed_tests": 20,
            "skipped_tests": 10,
            "errored_tests": 10,
            "aggregate_rate": 96.0,
            "module_results": [
                {"module_name": "fs", "total": 200, "passed": 190, "failed": 10, "pass_rate": 95.0},
                {"module_name": "http", "total": 300, "passed": 285, "failed": 15, "pass_rate": 95.0},
            ],
            "duration_seconds": 1200.0,
        }
        base.update(overrides)
        return base

    def test_valid_result(self):
        result = self._make_result()
        valid, errors = mod.validate_corpus_result(result)
        self.assertTrue(valid, f"Expected valid, got errors: {errors}")
        self.assertEqual(len(errors), 0)

    def test_missing_run_id(self):
        result = self._make_result()
        del result["run_id"]
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)
        self.assertTrue(any("run_id" in e for e in errors))

    def test_missing_timestamp(self):
        result = self._make_result()
        del result["timestamp"]
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)
        self.assertTrue(any("timestamp" in e for e in errors))

    def test_missing_total_tests(self):
        result = self._make_result()
        del result["total_tests"]
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)

    def test_missing_aggregate_rate(self):
        result = self._make_result()
        del result["aggregate_rate"]
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)

    def test_missing_module_results(self):
        result = self._make_result()
        del result["module_results"]
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)
        self.assertTrue(any("module_results" in e for e in errors))

    def test_missing_duration_seconds(self):
        result = self._make_result()
        del result["duration_seconds"]
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)

    def test_total_tests_mismatch(self):
        result = self._make_result(total_tests=999)
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)
        self.assertTrue(any("mismatch" in e for e in errors))

    def test_aggregate_rate_mismatch(self):
        result = self._make_result(aggregate_rate=50.0)
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)
        self.assertTrue(any("aggregate_rate" in e for e in errors))

    def test_aggregate_rate_within_tolerance(self):
        # 960 / 1000 * 100 = 96.0; 96.005 is within 0.01 tolerance
        result = self._make_result(aggregate_rate=96.005)
        valid, errors = mod.validate_corpus_result(result)
        self.assertTrue(valid, f"Expected valid within tolerance, got errors: {errors}")

    def test_aggregate_rate_outside_tolerance(self):
        # 960 / 1000 * 100 = 96.0; 96.02 is outside 0.01 tolerance
        result = self._make_result(aggregate_rate=96.02)
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)

    def test_empty_module_results(self):
        result = self._make_result(module_results=[])
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)
        self.assertTrue(any("non-empty" in e for e in errors))

    def test_module_results_not_list(self):
        result = self._make_result(module_results="not a list")
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)

    def test_module_missing_module_name(self):
        result = self._make_result(module_results=[
            {"total": 100, "passed": 90, "failed": 10, "pass_rate": 90.0}
        ])
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)
        self.assertTrue(any("module_name" in e for e in errors))

    def test_module_missing_pass_rate(self):
        result = self._make_result(module_results=[
            {"module_name": "fs", "total": 100, "passed": 90, "failed": 10}
        ])
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)
        self.assertTrue(any("pass_rate" in e for e in errors))

    def test_module_pass_rate_negative(self):
        result = self._make_result(module_results=[
            {"module_name": "fs", "total": 100, "passed": 90, "failed": 10, "pass_rate": -1.0}
        ])
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)
        self.assertTrue(any("out of range" in e for e in errors))

    def test_module_pass_rate_over_100(self):
        result = self._make_result(module_results=[
            {"module_name": "fs", "total": 100, "passed": 90, "failed": 10, "pass_rate": 101.0}
        ])
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)
        self.assertTrue(any("out of range" in e for e in errors))

    def test_module_pass_rate_exactly_0(self):
        result = self._make_result(module_results=[
            {"module_name": "fs", "total": 100, "passed": 0, "failed": 100, "pass_rate": 0.0}
        ])
        valid, errors = mod.validate_corpus_result(result)
        # pass_rate=0.0 is valid (in range), but aggregate_rate will mismatch
        rate_errors = [e for e in errors if "out of range" in e]
        self.assertEqual(len(rate_errors), 0)

    def test_module_pass_rate_exactly_100(self):
        result = self._make_result(module_results=[
            {"module_name": "fs", "total": 100, "passed": 100, "failed": 0, "pass_rate": 100.0}
        ])
        valid, errors = mod.validate_corpus_result(result)
        rate_errors = [e for e in errors if "out of range" in e]
        self.assertEqual(len(rate_errors), 0)

    def test_negative_duration(self):
        result = self._make_result(duration_seconds=-1.0)
        valid, errors = mod.validate_corpus_result(result)
        self.assertFalse(valid)
        self.assertTrue(any("duration" in e for e in errors))

    def test_zero_duration(self):
        result = self._make_result(duration_seconds=0.0)
        valid, errors = mod.validate_corpus_result(result)
        # duration=0 is valid (>= 0)
        dur_errors = [e for e in errors if "duration" in e]
        self.assertEqual(len(dur_errors), 0)

    def test_completely_empty_result(self):
        valid, errors = mod.validate_corpus_result({})
        self.assertFalse(valid)
        self.assertEqual(len(errors), 10)  # 10 required fields missing

    def test_multiple_modules_valid(self):
        result = self._make_result(module_results=[
            {"module_name": "fs", "total": 200, "passed": 190, "failed": 10, "pass_rate": 95.0},
            {"module_name": "http", "total": 300, "passed": 285, "failed": 15, "pass_rate": 95.0},
            {"module_name": "net", "total": 100, "passed": 95, "failed": 5, "pass_rate": 95.0},
        ])
        valid, errors = mod.validate_corpus_result(result)
        self.assertTrue(valid, f"Expected valid, got: {errors}")


# ---------------------------------------------------------------------------
# Test: pass_rate_to_tier
# ---------------------------------------------------------------------------

class TestPassRateToTier(unittest.TestCase):
    def test_g0_zero(self):
        self.assertEqual(mod.pass_rate_to_tier(0), "G0")

    def test_g0_boundary_low(self):
        self.assertEqual(mod.pass_rate_to_tier(79.99), "G0")

    def test_g1_boundary_low(self):
        self.assertEqual(mod.pass_rate_to_tier(80), "G1")

    def test_g1_boundary_high(self):
        self.assertEqual(mod.pass_rate_to_tier(89.99), "G1")

    def test_g2_boundary_low(self):
        self.assertEqual(mod.pass_rate_to_tier(90), "G2")

    def test_g2_boundary_high(self):
        self.assertEqual(mod.pass_rate_to_tier(94.99), "G2")

    def test_g3_boundary_low(self):
        self.assertEqual(mod.pass_rate_to_tier(95), "G3")

    def test_g3_boundary_high(self):
        self.assertEqual(mod.pass_rate_to_tier(99.99), "G3")

    def test_g4_exactly_100(self):
        self.assertEqual(mod.pass_rate_to_tier(100), "G4")

    def test_g0_at_50(self):
        self.assertEqual(mod.pass_rate_to_tier(50), "G0")

    def test_g1_at_85(self):
        self.assertEqual(mod.pass_rate_to_tier(85), "G1")

    def test_g2_at_92(self):
        self.assertEqual(mod.pass_rate_to_tier(92), "G2")

    def test_g3_at_97(self):
        self.assertEqual(mod.pass_rate_to_tier(97), "G3")


# ---------------------------------------------------------------------------
# Test: check_regression
# ---------------------------------------------------------------------------

class TestCheckRegression(unittest.TestCase):
    def test_no_regression_equal(self):
        is_reg, delta = mod.check_regression(95.0, 95.0)
        self.assertFalse(is_reg)
        self.assertEqual(delta, 0.0)

    def test_no_regression_increase(self):
        is_reg, delta = mod.check_regression(96.0, 95.0)
        self.assertFalse(is_reg)
        self.assertEqual(delta, 0.0)

    def test_regression_detected(self):
        is_reg, delta = mod.check_regression(94.0, 95.0)
        self.assertTrue(is_reg)
        self.assertAlmostEqual(delta, 1.0)

    def test_regression_small_delta(self):
        is_reg, delta = mod.check_regression(94.99, 95.0)
        self.assertTrue(is_reg)
        self.assertAlmostEqual(delta, 0.01, places=4)

    def test_regression_large_delta(self):
        is_reg, delta = mod.check_regression(50.0, 95.0)
        self.assertTrue(is_reg)
        self.assertAlmostEqual(delta, 45.0)

    def test_no_regression_from_zero(self):
        is_reg, delta = mod.check_regression(95.0, 0.0)
        self.assertFalse(is_reg)
        self.assertEqual(delta, 0.0)

    def test_regression_to_zero(self):
        is_reg, delta = mod.check_regression(0.0, 95.0)
        self.assertTrue(is_reg)
        self.assertAlmostEqual(delta, 95.0)


# ---------------------------------------------------------------------------
# Test: constants
# ---------------------------------------------------------------------------

class TestConstants(unittest.TestCase):
    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_event_codes_prefix(self):
        for code in mod.EVENT_CODES:
            self.assertTrue(code.startswith("CCG-"))

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_invariants_prefix(self):
        for inv in mod.INVARIANTS:
            self.assertTrue(inv.startswith("INV-CCG-"))

    def test_gate_tiers_count(self):
        self.assertEqual(len(mod.GATE_TIERS), 5)

    def test_gate_tiers_sequence(self):
        self.assertEqual(mod.GATE_TIERS, ["G0", "G1", "G2", "G3", "G4"])

    def test_all_checks_count(self):
        self.assertEqual(len(mod.ALL_CHECKS), 20)

    def test_all_checks_are_callable(self):
        for fn in mod.ALL_CHECKS:
            self.assertTrue(callable(fn))


# ---------------------------------------------------------------------------
# Test: missing file detection
# ---------------------------------------------------------------------------

class TestMissingFileDetection(unittest.TestCase):
    def test_missing_spec_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "spec.md"
        with patch.object(mod, "SPEC", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(len(failed) > 0)
        self.assertTrue(any("spec" in c["check"].lower() for c in failed))

    def test_missing_policy_detected(self):
        fake = ROOT / "does" / "not" / "exist" / "policy.md"
        with patch.object(mod, "POLICY", fake):
            report = mod.run_all()
        failed = [c for c in report["checks"] if not c["pass"]]
        self.assertTrue(len(failed) > 0)
        self.assertTrue(any("policy" in c["check"].lower() for c in failed))

    def test_missing_spec_causes_fail_verdict(self):
        fake = ROOT / "does" / "not" / "exist" / "spec.md"
        with patch.object(mod, "SPEC", fake):
            report = mod.run_all()
        self.assertEqual(report["verdict"], "FAIL")

    def test_missing_policy_causes_fail_verdict(self):
        fake = ROOT / "does" / "not" / "exist" / "policy.md"
        with patch.object(mod, "POLICY", fake):
            report = mod.run_all()
        self.assertEqual(report["verdict"], "FAIL")


# ---------------------------------------------------------------------------
# Test: JSON output
# ---------------------------------------------------------------------------

class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-28sz")

    def test_json_flag_via_subprocess(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_compat_corpus_gate.py"), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-28sz")
        self.assertEqual(data["verdict"], "PASS")

    def test_json_has_title(self):
        result = mod.run_all()
        self.assertIn("title", result)
        self.assertIn("corpus", result["title"].lower())


# ---------------------------------------------------------------------------
# Test: safe_rel
# ---------------------------------------------------------------------------

class TestSafeRel(unittest.TestCase):
    def test_safe_rel_with_root_path(self):
        p = mod.ROOT / "some" / "file.txt"
        result = mod._safe_rel(p)
        self.assertFalse(result.startswith("/"))

    def test_safe_rel_with_non_root_path(self):
        p = Path("/tmp/fakepath/file.txt")
        result = mod._safe_rel(p)
        self.assertEqual(result, "/tmp/fakepath/file.txt")

    def test_safe_rel_returns_string(self):
        p = mod.ROOT / "docs" / "test.md"
        result = mod._safe_rel(p)
        self.assertIsInstance(result, str)


if __name__ == "__main__":
    unittest.main()
