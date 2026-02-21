"""Unit tests for scripts/check_fallback_trigger.py (bd-3v8f: fallback trigger contract)."""

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
    "check_fallback_trigger",
    ROOT / "scripts" / "check_fallback_trigger.py",
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
        for key in ["bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_bead_id(self):
        self.assertEqual(mod.run_all()["bead_id"], "bd-3v8f")

    def test_title(self):
        self.assertEqual(mod.run_all()["title"], "Fallback trigger contract field")

    def test_section(self):
        self.assertEqual(mod.run_all()["section"], "11")

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

    def test_total_matches_checks_length(self):
        result = mod.run_all()
        self.assertEqual(result["total"], len(result["checks"]))

    def test_passed_count_matches(self):
        result = mod.run_all()
        actual_passed = sum(1 for c in result["checks"] if c["pass"])
        self.assertEqual(result["passed"], actual_passed)


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
# Test: individual check functions
# ---------------------------------------------------------------------------

class TestIndividualChecks(unittest.TestCase):
    def _run_check(self, fn):
        mod.RESULTS.clear()
        fn()
        self.assertGreater(len(mod.RESULTS), 0)
        return mod.RESULTS[-1]

    def test_check_spec_exists(self):
        result = self._run_check(mod.check_spec_exists)
        self.assertTrue(result["pass"])

    def test_check_policy_exists(self):
        result = self._run_check(mod.check_policy_exists)
        self.assertTrue(result["pass"])

    def test_check_spec_fallback_trigger_keyword(self):
        result = self._run_check(mod.check_spec_fallback_trigger_keyword)
        self.assertTrue(result["pass"])

    def test_check_spec_deterministic_keyword(self):
        result = self._run_check(mod.check_spec_deterministic_keyword)
        self.assertTrue(result["pass"])

    def test_check_spec_rollback_mechanisms(self):
        result = self._run_check(mod.check_spec_rollback_mechanisms)
        self.assertTrue(result["pass"])

    def test_check_spec_required_fields(self):
        result = self._run_check(mod.check_spec_required_fields)
        self.assertTrue(result["pass"])

    def test_check_spec_event_codes(self):
        result = self._run_check(mod.check_spec_event_codes)
        self.assertTrue(result["pass"])

    def test_check_spec_invariants(self):
        result = self._run_check(mod.check_spec_invariants)
        self.assertTrue(result["pass"])

    def test_check_spec_detection_latency_threshold(self):
        result = self._run_check(mod.check_spec_detection_latency_threshold)
        self.assertTrue(result["pass"])

    def test_check_spec_rto_threshold(self):
        result = self._run_check(mod.check_spec_rto_threshold)
        self.assertTrue(result["pass"])

    def test_check_spec_coverage_requirement(self):
        result = self._run_check(mod.check_spec_coverage_requirement)
        self.assertTrue(result["pass"])

    def test_check_spec_safe_state_keyword(self):
        result = self._run_check(mod.check_spec_safe_state_keyword)
        self.assertTrue(result["pass"])

    def test_check_policy_contract_fields(self):
        result = self._run_check(mod.check_policy_contract_fields)
        self.assertTrue(result["pass"])

    def test_check_policy_rollback_mechanisms(self):
        result = self._run_check(mod.check_policy_rollback_mechanisms)
        self.assertTrue(result["pass"])

    def test_check_policy_governance(self):
        result = self._run_check(mod.check_policy_governance)
        self.assertTrue(result["pass"])

    def test_check_policy_appeal_process(self):
        result = self._run_check(mod.check_policy_appeal_process)
        self.assertTrue(result["pass"])

    def test_check_policy_event_codes(self):
        result = self._run_check(mod.check_policy_event_codes)
        self.assertTrue(result["pass"])

    def test_check_policy_invariants(self):
        result = self._run_check(mod.check_policy_invariants)
        self.assertTrue(result["pass"])

    def test_check_policy_timing_guarantees(self):
        result = self._run_check(mod.check_policy_timing_guarantees)
        self.assertTrue(result["pass"])

    def test_check_policy_downgrade_triggers(self):
        result = self._run_check(mod.check_policy_downgrade_triggers)
        self.assertTrue(result["pass"])

    def test_check_policy_validation_rules(self):
        result = self._run_check(mod.check_policy_validation_rules)
        self.assertTrue(result["pass"])

    def test_check_policy_audit_trail(self):
        result = self._run_check(mod.check_policy_audit_trail)
        self.assertTrue(result["pass"])


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

    def test_both_missing_causes_all_checks_fail(self):
        fake_spec = ROOT / "does" / "not" / "exist" / "spec.md"
        fake_policy = ROOT / "does" / "not" / "exist" / "policy.md"
        with patch.object(mod, "SPEC", fake_spec), patch.object(mod, "POLICY", fake_policy):
            report = mod.run_all()
        self.assertEqual(report["passed"], 0)
        self.assertEqual(report["failed"], report["total"])


# ---------------------------------------------------------------------------
# Test: validate_fallback_trigger helper
# ---------------------------------------------------------------------------

class TestValidateFallbackTrigger(unittest.TestCase):
    def _make_obj(self, **overrides):
        obj = {
            "trigger_conditions": [
                "health_check_failure_count >= 3 within 10s",
                "error_rate > 0.05 over 60s sliding window",
            ],
            "fallback_target_state": "v2.3.1-stable",
            "rollback_mechanism": "automatic",
            "max_detection_latency_s": 2,
            "recovery_time_objective_s": 10,
            "subsystem_id": "connector-lifecycle",
            "rationale": "Connector lifecycle is critical for availability.",
        }
        obj.update(overrides)
        return obj

    def test_valid_automatic(self):
        obj = self._make_obj()
        results = mod.validate_fallback_trigger(obj)
        for r in results:
            self.assertTrue(r["passed"], f"Failed: {r['name']}: {r['detail']}")

    def test_valid_semi_automatic(self):
        obj = self._make_obj(rollback_mechanism="semi-automatic")
        results = mod.validate_fallback_trigger(obj)
        rm_check = [r for r in results if r["name"] == "rollback_mechanism_valid"][0]
        self.assertTrue(rm_check["passed"])

    def test_valid_manual(self):
        obj = self._make_obj(rollback_mechanism="manual")
        results = mod.validate_fallback_trigger(obj)
        rm_check = [r for r in results if r["name"] == "rollback_mechanism_valid"][0]
        self.assertTrue(rm_check["passed"])

    def test_invalid_rollback_mechanism(self):
        obj = self._make_obj(rollback_mechanism="fast-forward")
        results = mod.validate_fallback_trigger(obj)
        rm_check = [r for r in results if r["name"] == "rollback_mechanism_valid"][0]
        self.assertFalse(rm_check["passed"])

    def test_empty_trigger_conditions(self):
        obj = self._make_obj(trigger_conditions=[])
        results = mod.validate_fallback_trigger(obj)
        tc_check = [r for r in results if r["name"] == "trigger_conditions_valid"][0]
        self.assertFalse(tc_check["passed"])

    def test_trigger_conditions_with_empty_string(self):
        obj = self._make_obj(trigger_conditions=["valid", ""])
        results = mod.validate_fallback_trigger(obj)
        tc_check = [r for r in results if r["name"] == "trigger_conditions_valid"][0]
        self.assertFalse(tc_check["passed"])

    def test_trigger_conditions_not_list(self):
        obj = self._make_obj(trigger_conditions="not a list")
        results = mod.validate_fallback_trigger(obj)
        tc_check = [r for r in results if r["name"] == "trigger_conditions_valid"][0]
        self.assertFalse(tc_check["passed"])

    def test_empty_fallback_target_state(self):
        obj = self._make_obj(fallback_target_state="")
        results = mod.validate_fallback_trigger(obj)
        fts_check = [r for r in results if r["name"] == "fallback_target_state_valid"][0]
        self.assertFalse(fts_check["passed"])

    def test_missing_fallback_target_state(self):
        obj = self._make_obj()
        del obj["fallback_target_state"]
        results = mod.validate_fallback_trigger(obj)
        fts_check = [r for r in results if r["name"] == "fallback_target_state_valid"][0]
        self.assertFalse(fts_check["passed"])

    def test_detection_latency_at_boundary(self):
        obj = self._make_obj(max_detection_latency_s=5)
        results = mod.validate_fallback_trigger(obj)
        mdl_check = [r for r in results if r["name"] == "max_detection_latency_valid"][0]
        self.assertTrue(mdl_check["passed"])

    def test_detection_latency_exceeds_max(self):
        obj = self._make_obj(max_detection_latency_s=6)
        results = mod.validate_fallback_trigger(obj)
        mdl_check = [r for r in results if r["name"] == "max_detection_latency_valid"][0]
        self.assertFalse(mdl_check["passed"])

    def test_detection_latency_zero(self):
        obj = self._make_obj(max_detection_latency_s=0)
        results = mod.validate_fallback_trigger(obj)
        mdl_check = [r for r in results if r["name"] == "max_detection_latency_valid"][0]
        self.assertFalse(mdl_check["passed"])

    def test_detection_latency_negative(self):
        obj = self._make_obj(max_detection_latency_s=-1)
        results = mod.validate_fallback_trigger(obj)
        mdl_check = [r for r in results if r["name"] == "max_detection_latency_valid"][0]
        self.assertFalse(mdl_check["passed"])

    def test_rto_at_boundary(self):
        obj = self._make_obj(recovery_time_objective_s=30)
        results = mod.validate_fallback_trigger(obj)
        rto_check = [r for r in results if r["name"] == "recovery_time_objective_valid"][0]
        self.assertTrue(rto_check["passed"])

    def test_rto_exceeds_max(self):
        obj = self._make_obj(recovery_time_objective_s=31)
        results = mod.validate_fallback_trigger(obj)
        rto_check = [r for r in results if r["name"] == "recovery_time_objective_valid"][0]
        self.assertFalse(rto_check["passed"])

    def test_rto_zero(self):
        obj = self._make_obj(recovery_time_objective_s=0)
        results = mod.validate_fallback_trigger(obj)
        rto_check = [r for r in results if r["name"] == "recovery_time_objective_valid"][0]
        self.assertFalse(rto_check["passed"])

    def test_rto_negative(self):
        obj = self._make_obj(recovery_time_objective_s=-5)
        results = mod.validate_fallback_trigger(obj)
        rto_check = [r for r in results if r["name"] == "recovery_time_objective_valid"][0]
        self.assertFalse(rto_check["passed"])

    def test_empty_subsystem_id(self):
        obj = self._make_obj(subsystem_id="")
        results = mod.validate_fallback_trigger(obj)
        sid_check = [r for r in results if r["name"] == "subsystem_id_valid"][0]
        self.assertFalse(sid_check["passed"])

    def test_empty_rationale(self):
        obj = self._make_obj(rationale="")
        results = mod.validate_fallback_trigger(obj)
        rat_check = [r for r in results if r["name"] == "rationale_valid"][0]
        self.assertFalse(rat_check["passed"])

    def test_missing_rationale(self):
        obj = self._make_obj()
        del obj["rationale"]
        results = mod.validate_fallback_trigger(obj)
        rat_check = [r for r in results if r["name"] == "rationale_valid"][0]
        self.assertFalse(rat_check["passed"])

    def test_single_trigger_condition(self):
        obj = self._make_obj(trigger_conditions=["single_condition"])
        results = mod.validate_fallback_trigger(obj)
        tc_check = [r for r in results if r["name"] == "trigger_conditions_valid"][0]
        self.assertTrue(tc_check["passed"])

    def test_float_latency(self):
        obj = self._make_obj(max_detection_latency_s=2.5)
        results = mod.validate_fallback_trigger(obj)
        mdl_check = [r for r in results if r["name"] == "max_detection_latency_valid"][0]
        self.assertTrue(mdl_check["passed"])

    def test_float_rto(self):
        obj = self._make_obj(recovery_time_objective_s=15.5)
        results = mod.validate_fallback_trigger(obj)
        rto_check = [r for r in results if r["name"] == "recovery_time_objective_valid"][0]
        self.assertTrue(rto_check["passed"])

    def test_result_count(self):
        obj = self._make_obj()
        results = mod.validate_fallback_trigger(obj)
        self.assertEqual(len(results), 7)

    def test_all_result_names_unique(self):
        obj = self._make_obj()
        results = mod.validate_fallback_trigger(obj)
        names = [r["name"] for r in results]
        self.assertEqual(len(names), len(set(names)))


# ---------------------------------------------------------------------------
# Test: compute_total_recovery_time helper
# ---------------------------------------------------------------------------

class TestComputeTotalRecoveryTime(unittest.TestCase):
    def test_typical_values(self):
        result = mod.compute_total_recovery_time(2.0, 10.0)
        self.assertAlmostEqual(result, 12.0)

    def test_max_values(self):
        result = mod.compute_total_recovery_time(5.0, 30.0)
        self.assertAlmostEqual(result, 35.0)

    def test_min_values(self):
        result = mod.compute_total_recovery_time(0.1, 0.5)
        self.assertAlmostEqual(result, 0.6)

    def test_zero_detection(self):
        result = mod.compute_total_recovery_time(0.0, 10.0)
        self.assertAlmostEqual(result, 10.0)

    def test_integer_inputs(self):
        result = mod.compute_total_recovery_time(3, 15)
        self.assertEqual(result, 18)


# ---------------------------------------------------------------------------
# Test: constants
# ---------------------------------------------------------------------------

class TestConstants(unittest.TestCase):
    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_event_codes_prefix(self):
        for code in mod.EVENT_CODES:
            self.assertTrue(code.startswith("FBT-"), f"Event code {code} missing FBT- prefix")

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_invariants_prefix(self):
        for inv in mod.INVARIANTS:
            self.assertTrue(inv.startswith("INV-FBT-"), f"Invariant {inv} missing INV-FBT- prefix")

    def test_rollback_mechanisms_count(self):
        self.assertEqual(len(mod.ROLLBACK_MECHANISMS), 3)

    def test_required_fields_count(self):
        self.assertEqual(len(mod.REQUIRED_FIELDS), 7)

    def test_all_checks_count(self):
        self.assertEqual(len(mod.ALL_CHECKS), 22)

    def test_max_detection_latency(self):
        self.assertEqual(mod.MAX_DETECTION_LATENCY_S, 5)

    def test_max_recovery_time_objective(self):
        self.assertEqual(mod.MAX_RECOVERY_TIME_OBJECTIVE_S, 30)

    def test_event_codes_values(self):
        expected = ["FBT-001", "FBT-002", "FBT-003", "FBT-004"]
        self.assertEqual(mod.EVENT_CODES, expected)

    def test_invariants_values(self):
        expected = ["INV-FBT-DETECT", "INV-FBT-REVERT", "INV-FBT-SAFE", "INV-FBT-AUDIT"]
        self.assertEqual(mod.INVARIANTS, expected)

    def test_rollback_mechanisms_values(self):
        expected = ["automatic", "semi-automatic", "manual"]
        self.assertEqual(mod.ROLLBACK_MECHANISMS, expected)


# ---------------------------------------------------------------------------
# Test: JSON output
# ---------------------------------------------------------------------------

class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-3v8f")

    def test_json_flag_via_subprocess(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_fallback_trigger.py"), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-3v8f")
        self.assertEqual(data["verdict"], "PASS")

    def test_self_test_flag_via_subprocess(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_fallback_trigger.py"), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        self.assertIn("22/22", proc.stdout)


# ---------------------------------------------------------------------------
# Test: safe_rel with mock paths
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

    def test_safe_rel_preserves_relative(self):
        p = mod.ROOT / "docs" / "specs" / "test.md"
        result = mod._safe_rel(p)
        self.assertEqual(result, "docs/specs/test.md")

    def test_safe_rel_with_root_itself(self):
        result = mod._safe_rel(mod.ROOT)
        self.assertEqual(result, ".")


if __name__ == "__main__":
    unittest.main()
