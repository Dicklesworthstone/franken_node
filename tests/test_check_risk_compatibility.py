"""Unit tests for scripts/check_risk_compatibility.py (bd-s4cu)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_risk_compatibility as mod


class TestSelfTest(unittest.TestCase):
    """self_test() must not raise."""

    def test_self_test(self) -> None:
        mod.self_test()


class TestRunAll(unittest.TestCase):
    """run_all() returns a well-formed result dict."""

    def test_structure(self) -> None:
        result = mod.run_all()
        self.assertIsInstance(result, dict)
        self.assertEqual(result["bead_id"], "bd-s4cu")
        self.assertEqual(result["section"], "12")
        self.assertIn("passed", result)
        self.assertIn("total", result)
        self.assertIn("all_passed", result)
        self.assertIn("checks", result)
        self.assertIsInstance(result["checks"], list)
        self.assertGreater(result["total"], 0)

    def test_check_names_unique(self) -> None:
        result = mod.run_all()
        names = [c["name"] for c in result["checks"]]
        self.assertEqual(len(names), len(set(names)), "Duplicate check names found")

    def test_passed_lte_total(self) -> None:
        result = mod.run_all()
        self.assertLessEqual(result["passed"], result["total"])

    def test_all_passed_consistency(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["all_passed"], result["passed"] == result["total"])


class TestIndividualChecks(unittest.TestCase):
    """Each individual check function populates RESULTS correctly."""

    def setUp(self) -> None:
        mod.RESULTS.clear()

    def test_check_spec_exists(self) -> None:
        mod.check_spec_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "spec_exists")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_risk_policy_exists(self) -> None:
        mod.check_risk_policy_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "risk_policy_exists")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_risk_documented(self) -> None:
        mod.check_risk_documented()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "risk_documented")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_countermeasures(self) -> None:
        mod.check_countermeasures()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "countermeasures")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_threshold(self) -> None:
        mod.check_threshold()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "threshold")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_event_codes(self) -> None:
        mod.check_event_codes()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "event_codes")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_invariants(self) -> None:
        mod.check_invariants()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "invariants")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_alert_pipeline(self) -> None:
        mod.check_alert_pipeline()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "alert_pipeline")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_spec_keywords(self) -> None:
        mod.check_spec_keywords()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "spec_keywords")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_escalation(self) -> None:
        mod.check_escalation()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "escalation")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_evidence_requirements(self) -> None:
        mod.check_evidence_requirements()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "evidence_requirements")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_verification_evidence(self) -> None:
        mod.check_verification_evidence()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "verification_evidence")
        self.assertTrue(mod.RESULTS[0]["passed"])

    def test_check_verification_summary(self) -> None:
        mod.check_verification_summary()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["name"], "verification_summary")
        self.assertTrue(mod.RESULTS[0]["passed"])


class TestCheckHelper(unittest.TestCase):
    """_check() appends to RESULTS correctly."""

    def setUp(self) -> None:
        mod.RESULTS.clear()

    def test_check_pass(self) -> None:
        mod._check("test_pass", True, "it passed")
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["passed"])
        self.assertEqual(mod.RESULTS[0]["name"], "test_pass")
        self.assertEqual(mod.RESULTS[0]["detail"], "it passed")

    def test_check_fail(self) -> None:
        mod._check("test_fail", False, "it failed")
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["passed"])


class TestJsonOutput(unittest.TestCase):
    """--json flag produces valid JSON."""

    def test_json_output(self) -> None:
        result = mod.run_all()
        output = json.dumps(result, indent=2)
        parsed = json.loads(output)
        self.assertEqual(parsed["bead_id"], "bd-s4cu")


if __name__ == "__main__":
    unittest.main()
