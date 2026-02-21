"""Unit tests for scripts/check_ev_score.py (bd-1jmq: EV score and tier)."""

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
    "check_ev_score",
    ROOT / "scripts" / "check_ev_score.py",
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
        for key in ["bead_id", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_bead_id(self):
        self.assertEqual(mod.run_all()["bead_id"], "bd-1jmq")

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

    def test_check_spec_ev_score_keyword(self):
        result = self._run_check(mod.check_spec_ev_score_keyword)
        self.assertTrue(result["pass"])

    def test_check_spec_tier_keyword(self):
        result = self._run_check(mod.check_spec_tier_keyword)
        self.assertTrue(result["pass"])

    def test_check_spec_tiers_defined(self):
        result = self._run_check(mod.check_spec_tiers_defined)
        self.assertTrue(result["pass"])

    def test_check_spec_verification_keyword(self):
        result = self._run_check(mod.check_spec_verification_keyword)
        self.assertTrue(result["pass"])

    def test_check_spec_weighted_keyword(self):
        result = self._run_check(mod.check_spec_weighted_keyword)
        self.assertTrue(result["pass"])

    def test_check_spec_event_codes(self):
        result = self._run_check(mod.check_spec_event_codes)
        self.assertTrue(result["pass"])

    def test_check_spec_invariants(self):
        result = self._run_check(mod.check_spec_invariants)
        self.assertTrue(result["pass"])

    def test_check_spec_tier_thresholds(self):
        result = self._run_check(mod.check_spec_tier_thresholds)
        self.assertTrue(result["pass"])

    def test_check_spec_upgrade_path(self):
        result = self._run_check(mod.check_spec_upgrade_path)
        self.assertTrue(result["pass"])

    def test_check_spec_downgrade_triggers(self):
        result = self._run_check(mod.check_spec_downgrade_triggers)
        self.assertTrue(result["pass"])

    def test_check_policy_dimensions(self):
        result = self._run_check(mod.check_policy_dimensions)
        self.assertTrue(result["pass"])

    def test_check_policy_weights(self):
        result = self._run_check(mod.check_policy_weights)
        self.assertTrue(result["pass"])

    def test_check_policy_governance(self):
        result = self._run_check(mod.check_policy_governance)
        self.assertTrue(result["pass"])

    def test_check_policy_appeal_process(self):
        result = self._run_check(mod.check_policy_appeal_process)
        self.assertTrue(result["pass"])

    def test_check_policy_tier_thresholds(self):
        result = self._run_check(mod.check_policy_tier_thresholds)
        self.assertTrue(result["pass"])

    def test_check_policy_event_codes(self):
        result = self._run_check(mod.check_policy_event_codes)
        self.assertTrue(result["pass"])

    def test_check_policy_invariants(self):
        result = self._run_check(mod.check_policy_invariants)
        self.assertTrue(result["pass"])

    def test_check_policy_downgrade_triggers(self):
        result = self._run_check(mod.check_policy_downgrade_triggers)
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


# ---------------------------------------------------------------------------
# Test: validate_ev_score helper
# ---------------------------------------------------------------------------

class TestValidateEvScore(unittest.TestCase):
    def _make_obj(self, **overrides):
        obj = {
            "ev_score": 72,
            "tier": "T3",
            "dimension_scores": {
                "code_review": {"score": 0.85, "evidence_ref": "ref1", "assessed_at": "2026-02-20T12:00:00Z"},
                "test_coverage": {"score": 0.90, "evidence_ref": "ref2", "assessed_at": "2026-02-20T12:00:00Z"},
                "security_audit": {"score": 0.70, "evidence_ref": "ref3", "assessed_at": "2026-02-20T12:00:00Z"},
                "supply_chain": {"score": 0.60, "evidence_ref": "ref4", "assessed_at": "2026-02-20T12:00:00Z"},
                "conformance": {"score": 0.50, "evidence_ref": "ref5", "assessed_at": "2026-02-20T12:00:00Z"},
            },
            "rationale": "All dimensions assessed with evidence references.",
        }
        obj.update(overrides)
        return obj

    def test_valid_t3(self):
        obj = self._make_obj()
        results = mod.validate_ev_score(obj)
        for r in results:
            self.assertTrue(r["passed"], f"Failed: {r['name']}: {r['detail']}")

    def test_valid_t4(self):
        obj = self._make_obj(ev_score=85, tier="T4")
        results = mod.validate_ev_score(obj)
        tier_check = [r for r in results if r["name"] == "tier_matches_score"][0]
        self.assertTrue(tier_check["passed"])

    def test_valid_t2(self):
        obj = self._make_obj(ev_score=50, tier="T2")
        results = mod.validate_ev_score(obj)
        tier_check = [r for r in results if r["name"] == "tier_matches_score"][0]
        self.assertTrue(tier_check["passed"])

    def test_valid_t1(self):
        obj = self._make_obj(ev_score=25, tier="T1")
        results = mod.validate_ev_score(obj)
        tier_check = [r for r in results if r["name"] == "tier_matches_score"][0]
        self.assertTrue(tier_check["passed"])

    def test_valid_t0(self):
        obj = self._make_obj(ev_score=10, tier="T0")
        results = mod.validate_ev_score(obj)
        tier_check = [r for r in results if r["name"] == "tier_matches_score"][0]
        self.assertTrue(tier_check["passed"])

    def test_tier_mismatch_detected(self):
        obj = self._make_obj(ev_score=85, tier="T1")
        results = mod.validate_ev_score(obj)
        tier_check = [r for r in results if r["name"] == "tier_matches_score"][0]
        self.assertFalse(tier_check["passed"])

    def test_empty_rationale_detected(self):
        obj = self._make_obj(rationale="")
        results = mod.validate_ev_score(obj)
        rat_check = [r for r in results if r["name"] == "rationale_present"][0]
        self.assertFalse(rat_check["passed"])

    def test_ev_score_out_of_range(self):
        obj = self._make_obj(ev_score=150)
        results = mod.validate_ev_score(obj)
        range_check = [r for r in results if r["name"] == "ev_score_range"][0]
        self.assertFalse(range_check["passed"])

    def test_invalid_tier_value(self):
        obj = self._make_obj(tier="T5")
        results = mod.validate_ev_score(obj)
        tier_check = [r for r in results if r["name"] == "tier_valid"][0]
        self.assertFalse(tier_check["passed"])


# ---------------------------------------------------------------------------
# Test: compute_ev_score helper
# ---------------------------------------------------------------------------

class TestComputeEvScore(unittest.TestCase):
    def test_all_ones(self):
        scores = {d: 1.0 for d in mod.DIMENSIONS}
        self.assertEqual(mod.compute_ev_score(scores), 100)

    def test_all_zeros(self):
        scores = {d: 0.0 for d in mod.DIMENSIONS}
        self.assertEqual(mod.compute_ev_score(scores), 0)

    def test_mixed_scores(self):
        scores = {
            "code_review": 0.85,
            "test_coverage": 0.90,
            "security_audit": 0.70,
            "supply_chain": 0.60,
            "conformance": 0.80,
        }
        # 0.20*0.85 + 0.20*0.90 + 0.25*0.70 + 0.15*0.60 + 0.20*0.80
        # = 0.17 + 0.18 + 0.175 + 0.09 + 0.16 = 0.775 -> 78
        self.assertEqual(mod.compute_ev_score(scores), 78)


# ---------------------------------------------------------------------------
# Test: score_to_tier helper
# ---------------------------------------------------------------------------

class TestScoreToTier(unittest.TestCase):
    def test_t0_boundary(self):
        self.assertEqual(mod.score_to_tier(0), "T0")
        self.assertEqual(mod.score_to_tier(19), "T0")

    def test_t1_boundary(self):
        self.assertEqual(mod.score_to_tier(20), "T1")
        self.assertEqual(mod.score_to_tier(39), "T1")

    def test_t2_boundary(self):
        self.assertEqual(mod.score_to_tier(40), "T2")
        self.assertEqual(mod.score_to_tier(59), "T2")

    def test_t3_boundary(self):
        self.assertEqual(mod.score_to_tier(60), "T3")
        self.assertEqual(mod.score_to_tier(79), "T3")

    def test_t4_boundary(self):
        self.assertEqual(mod.score_to_tier(80), "T4")
        self.assertEqual(mod.score_to_tier(100), "T4")


# ---------------------------------------------------------------------------
# Test: constants
# ---------------------------------------------------------------------------

class TestConstants(unittest.TestCase):
    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_tier_labels_count(self):
        self.assertEqual(len(mod.TIER_LABELS), 5)

    def test_dimensions_count(self):
        self.assertEqual(len(mod.DIMENSIONS), 5)

    def test_all_checks_count(self):
        self.assertEqual(len(mod.ALL_CHECKS), 20)

    def test_dimension_weights_sum_to_one(self):
        total = sum(mod.DIMENSION_WEIGHTS.values())
        self.assertAlmostEqual(total, 1.0, places=9)


# ---------------------------------------------------------------------------
# Test: JSON output
# ---------------------------------------------------------------------------

class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-1jmq")

    def test_json_flag_via_subprocess(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_ev_score.py"), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-1jmq")
        self.assertEqual(data["verdict"], "PASS")


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


if __name__ == "__main__":
    unittest.main()
