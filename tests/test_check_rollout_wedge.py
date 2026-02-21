"""Unit tests for scripts/check_rollout_wedge.py (bd-2ymp)."""
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
    "check_rollout_wedge", ROOT / "scripts" / "check_rollout_wedge.py"
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# TestRunAllStructure
# ---------------------------------------------------------------------------

class TestRunAllStructure(unittest.TestCase):
    def test_returns_dict(self):
        result = mod.run_all()
        self.assertIsInstance(result, dict)

    def test_has_required_keys(self):
        result = mod.run_all()
        for key in ("bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"):
            self.assertIn(key, result)

    def test_bead_id(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-2ymp")

    def test_section(self):
        result = mod.run_all()
        self.assertEqual(result["section"], "11")

    def test_checks_is_list(self):
        result = mod.run_all()
        self.assertIsInstance(result["checks"], list)

    def test_all_checks_have_required_keys(self):
        result = mod.run_all()
        for entry in result["checks"]:
            self.assertIn("check", entry)
            self.assertIn("pass", entry)
            self.assertIn("detail", entry)

    def test_pass_values_are_bool(self):
        result = mod.run_all()
        for entry in result["checks"]:
            self.assertIsInstance(entry["pass"], bool)

    def test_minimum_check_count(self):
        result = mod.run_all()
        self.assertGreaterEqual(len(result["checks"]), 50,
                                f"Expected >= 50 checks, got {len(result['checks'])}")

    def test_total_equals_checks_length(self):
        result = mod.run_all()
        self.assertEqual(result["total"], len(result["checks"]))

    def test_passed_plus_failed_equals_total(self):
        result = mod.run_all()
        self.assertEqual(result["passed"] + result["failed"], result["total"])


# ---------------------------------------------------------------------------
# TestSelfTest
# ---------------------------------------------------------------------------

class TestSelfTest(unittest.TestCase):
    def test_self_test_returns_bool(self):
        result = mod.self_test()
        self.assertIsInstance(result, bool)

    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


# ---------------------------------------------------------------------------
# TestIndividualChecks -- verify all checks pass
# ---------------------------------------------------------------------------

class TestIndividualChecks(unittest.TestCase):
    def test_all_checks_pass(self):
        result = mod.run_all()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            f"Failing checks: {json.dumps(failing, indent=2)}"
        )

    def test_verdict_is_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS")


# ---------------------------------------------------------------------------
# TestMissingFileDetection
# ---------------------------------------------------------------------------

class TestMissingFileDetection(unittest.TestCase):
    def test_missing_spec_detected(self):
        with patch.object(mod, "SPEC", Path("/nonexistent/spec.md")):
            result = mod.run_all()
            spec_check = next(c for c in result["checks"] if c["check"] == "file: spec contract")
            self.assertFalse(spec_check["pass"])
            self.assertIn("MISSING", spec_check["detail"])

    def test_missing_policy_detected(self):
        with patch.object(mod, "POLICY", Path("/nonexistent/policy.md")):
            result = mod.run_all()
            pol_check = next(c for c in result["checks"] if c["check"] == "file: policy document")
            self.assertFalse(pol_check["pass"])
            self.assertIn("MISSING", pol_check["detail"])

    def test_missing_spec_cascades_to_field_checks(self):
        with patch.object(mod, "SPEC", Path("/nonexistent/spec.md")):
            result = mod.run_all()
            field_checks = [c for c in result["checks"] if c["check"].startswith("spec field:")]
            for c in field_checks:
                self.assertFalse(c["pass"])
                self.assertEqual(c["detail"], "spec missing")


# ---------------------------------------------------------------------------
# TestValidateRolloutWedge
# ---------------------------------------------------------------------------

class TestValidateRolloutWedge(unittest.TestCase):
    def _valid_wedge(self):
        return {
            "wedge_stages": [
                {
                    "stage_id": "canary",
                    "target_percentage": 5,
                    "duration_hours": 2.0,
                    "success_criteria": ["error_rate < 0.01"],
                    "rollback_trigger": "error_rate > 0.05",
                },
                {
                    "stage_id": "wide",
                    "target_percentage": 50,
                    "duration_hours": 4.0,
                    "success_criteria": ["error_rate < 0.01", "p99 < 200ms"],
                    "rollback_trigger": "error_rate > 0.05",
                },
            ],
            "initial_percentage": 5,
            "increment_policy": "linear",
            "max_blast_radius": 50,
            "observation_window_hours": 1.0,
            "wedge_state": "PENDING",
        }

    def test_valid_wedge_passes(self):
        valid, errors = mod.validate_rollout_wedge(self._valid_wedge())
        self.assertTrue(valid, f"Errors: {errors}")
        self.assertEqual(errors, [])

    def test_missing_wedge_stages(self):
        w = self._valid_wedge()
        del w["wedge_stages"]
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)
        self.assertTrue(any("wedge_stages" in e for e in errors))

    def test_single_stage_rejected(self):
        w = self._valid_wedge()
        w["wedge_stages"] = [w["wedge_stages"][0]]
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)
        self.assertTrue(any("at least 2" in e for e in errors))

    def test_non_increasing_percentage(self):
        w = self._valid_wedge()
        w["wedge_stages"][1]["target_percentage"] = 3  # < stage 0's 5
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)
        self.assertTrue(any("monotonically increasing" in e for e in errors))

    def test_invalid_increment_policy(self):
        w = self._valid_wedge()
        w["increment_policy"] = "random"
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)
        self.assertTrue(any("increment_policy" in e for e in errors))

    def test_invalid_wedge_state(self):
        w = self._valid_wedge()
        w["wedge_state"] = "UNKNOWN"
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)
        self.assertTrue(any("wedge_state" in e for e in errors))

    def test_zero_initial_percentage(self):
        w = self._valid_wedge()
        w["initial_percentage"] = 0
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)
        self.assertTrue(any("initial_percentage" in e for e in errors))

    def test_negative_initial_percentage(self):
        w = self._valid_wedge()
        w["initial_percentage"] = -5
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)

    def test_observation_window_too_short(self):
        w = self._valid_wedge()
        w["observation_window_hours"] = 0.5
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)
        self.assertTrue(any("observation_window_hours" in e for e in errors))

    def test_invalid_max_blast_radius(self):
        w = self._valid_wedge()
        w["max_blast_radius"] = 0
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)
        self.assertTrue(any("max_blast_radius" in e for e in errors))

    def test_missing_stage_field(self):
        w = self._valid_wedge()
        del w["wedge_stages"][0]["rollback_trigger"]
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)
        self.assertTrue(any("rollback_trigger" in e for e in errors))

    def test_empty_success_criteria(self):
        w = self._valid_wedge()
        w["wedge_stages"][0]["success_criteria"] = []
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)
        self.assertTrue(any("success_criteria" in e for e in errors))

    def test_zero_duration_hours(self):
        w = self._valid_wedge()
        w["wedge_stages"][0]["duration_hours"] = 0
        valid, errors = mod.validate_rollout_wedge(w)
        self.assertFalse(valid)
        self.assertTrue(any("duration_hours" in e for e in errors))

    def test_all_increment_policies_valid(self):
        for pol in mod.INCREMENT_POLICIES:
            w = self._valid_wedge()
            w["increment_policy"] = pol
            valid, errors = mod.validate_rollout_wedge(w)
            self.assertTrue(valid, f"Policy {pol} should be valid, errors: {errors}")

    def test_all_wedge_states_valid(self):
        for state in mod.WEDGE_STATES:
            w = self._valid_wedge()
            w["wedge_state"] = state
            valid, errors = mod.validate_rollout_wedge(w)
            self.assertTrue(valid, f"State {state} should be valid, errors: {errors}")


# ---------------------------------------------------------------------------
# TestComputeTotalRolloutDuration
# ---------------------------------------------------------------------------

class TestComputeTotalRolloutDuration(unittest.TestCase):
    def test_basic_computation(self):
        wedge = {
            "wedge_stages": [
                {"duration_hours": 2.0},
                {"duration_hours": 4.0},
            ],
            "observation_window_hours": 1.0,
        }
        result = mod.compute_total_rollout_duration(wedge)
        # 2 + 4 + 1*2 = 8
        self.assertAlmostEqual(result, 8.0)

    def test_single_stage(self):
        wedge = {
            "wedge_stages": [{"duration_hours": 3.0}],
            "observation_window_hours": 2.0,
        }
        result = mod.compute_total_rollout_duration(wedge)
        # 3 + 2*1 = 5
        self.assertAlmostEqual(result, 5.0)

    def test_empty_stages(self):
        wedge = {"wedge_stages": [], "observation_window_hours": 1.0}
        result = mod.compute_total_rollout_duration(wedge)
        self.assertAlmostEqual(result, 0.0)

    def test_missing_observation_window(self):
        wedge = {
            "wedge_stages": [
                {"duration_hours": 2.0},
                {"duration_hours": 4.0},
            ],
        }
        result = mod.compute_total_rollout_duration(wedge)
        # 2 + 4 + 0*2 = 6
        self.assertAlmostEqual(result, 6.0)

    def test_three_stages(self):
        wedge = {
            "wedge_stages": [
                {"duration_hours": 1.0},
                {"duration_hours": 2.0},
                {"duration_hours": 4.0},
            ],
            "observation_window_hours": 1.5,
        }
        result = mod.compute_total_rollout_duration(wedge)
        # 1 + 2 + 4 + 1.5*3 = 11.5
        self.assertAlmostEqual(result, 11.5)


# ---------------------------------------------------------------------------
# TestConstants
# ---------------------------------------------------------------------------

class TestConstants(unittest.TestCase):
    def test_event_codes(self):
        self.assertEqual(mod.EVENT_CODES, ["RWG-001", "RWG-002", "RWG-003", "RWG-004"])

    def test_invariants(self):
        self.assertEqual(mod.INVARIANTS, [
            "INV-RWG-STAGED", "INV-RWG-OBSERVE", "INV-RWG-BLAST", "INV-RWG-ROLLBACK"
        ])

    def test_wedge_states(self):
        self.assertEqual(mod.WEDGE_STATES, [
            "PENDING", "ACTIVE", "PAUSED", "ROLLED_BACK", "COMPLETE"
        ])

    def test_increment_policies(self):
        self.assertEqual(mod.INCREMENT_POLICIES, ["linear", "exponential", "manual"])

    def test_four_event_codes(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_four_invariants(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_five_wedge_states(self):
        self.assertEqual(len(mod.WEDGE_STATES), 5)

    def test_three_increment_policies(self):
        self.assertEqual(len(mod.INCREMENT_POLICIES), 3)


# ---------------------------------------------------------------------------
# TestJsonOutput
# ---------------------------------------------------------------------------

class TestJsonOutput(unittest.TestCase):
    def test_cli_json(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_rollout_wedge.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, f"stderr: {result.stderr}")
        data = json.loads(result.stdout)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["bead_id"], "bd-2ymp")

    def test_cli_self_test(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_rollout_wedge.py"), "--self-test"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, f"stderr: {result.stderr}")
        self.assertIn("self_test:", result.stdout)

    def test_cli_human_readable(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_rollout_wedge.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, f"stderr: {result.stderr}")
        self.assertIn("verdict=PASS", result.stdout)


# ---------------------------------------------------------------------------
# TestSafeRel
# ---------------------------------------------------------------------------

class TestSafeRel(unittest.TestCase):
    def test_within_root(self):
        p = mod.ROOT / "docs" / "specs" / "section_11" / "bd-2ymp_contract.md"
        result = mod._safe_rel(p)
        self.assertEqual(result, "docs/specs/section_11/bd-2ymp_contract.md")

    def test_outside_root(self):
        p = Path("/tmp/some/random/path.md")
        result = mod._safe_rel(p)
        self.assertEqual(result, "/tmp/some/random/path.md")

    def test_root_itself(self):
        result = mod._safe_rel(mod.ROOT)
        self.assertEqual(result, ".")


# ---------------------------------------------------------------------------
# TestCheckHelper
# ---------------------------------------------------------------------------

class TestCheckHelper(unittest.TestCase):
    def test_pass_true_default_detail(self):
        mod.RESULTS = []
        entry = mod._check("test-check", True)
        self.assertTrue(entry["pass"])
        self.assertEqual(entry["detail"], "found")

    def test_pass_false_default_detail(self):
        mod.RESULTS = []
        entry = mod._check("test-check", False)
        self.assertFalse(entry["pass"])
        self.assertEqual(entry["detail"], "NOT FOUND")

    def test_custom_detail(self):
        mod.RESULTS = []
        entry = mod._check("test-check", True, "custom detail")
        self.assertEqual(entry["detail"], "custom detail")

    def test_appends_to_results(self):
        mod.RESULTS = []
        mod._check("a", True)
        mod._check("b", False)
        self.assertEqual(len(mod.RESULTS), 2)


# ---------------------------------------------------------------------------
# TestSpecificFileChecks
# ---------------------------------------------------------------------------

class TestSpecificFileChecks(unittest.TestCase):
    def test_spec_exists(self):
        result = mod.run_all()
        check = next(c for c in result["checks"] if c["check"] == "file: spec contract")
        self.assertTrue(check["pass"])

    def test_policy_exists(self):
        result = mod.run_all()
        check = next(c for c in result["checks"] if c["check"] == "file: policy document")
        self.assertTrue(check["pass"])


# ---------------------------------------------------------------------------
# TestSpecEventCodes
# ---------------------------------------------------------------------------

class TestSpecEventCodes(unittest.TestCase):
    def test_rwg_001(self):
        result = mod.run_all()
        check = next(c for c in result["checks"] if c["check"] == "spec event code: RWG-001")
        self.assertTrue(check["pass"])

    def test_rwg_002(self):
        result = mod.run_all()
        check = next(c for c in result["checks"] if c["check"] == "spec event code: RWG-002")
        self.assertTrue(check["pass"])

    def test_rwg_003(self):
        result = mod.run_all()
        check = next(c for c in result["checks"] if c["check"] == "spec event code: RWG-003")
        self.assertTrue(check["pass"])

    def test_rwg_004(self):
        result = mod.run_all()
        check = next(c for c in result["checks"] if c["check"] == "spec event code: RWG-004")
        self.assertTrue(check["pass"])


# ---------------------------------------------------------------------------
# TestSpecInvariants
# ---------------------------------------------------------------------------

class TestSpecInvariants(unittest.TestCase):
    def test_staged(self):
        result = mod.run_all()
        check = next(c for c in result["checks"] if c["check"] == "spec invariant: INV-RWG-STAGED")
        self.assertTrue(check["pass"])

    def test_observe(self):
        result = mod.run_all()
        check = next(c for c in result["checks"] if c["check"] == "spec invariant: INV-RWG-OBSERVE")
        self.assertTrue(check["pass"])

    def test_blast(self):
        result = mod.run_all()
        check = next(c for c in result["checks"] if c["check"] == "spec invariant: INV-RWG-BLAST")
        self.assertTrue(check["pass"])

    def test_rollback(self):
        result = mod.run_all()
        check = next(c for c in result["checks"] if c["check"] == "spec invariant: INV-RWG-ROLLBACK")
        self.assertTrue(check["pass"])


if __name__ == "__main__":
    unittest.main()
