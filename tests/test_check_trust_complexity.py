"""Unit tests for scripts/check_trust_complexity.py (bd-kiqr)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_trust_complexity as mod


class TestSelfTest(unittest.TestCase):
    """self_test() must not raise."""

    def test_self_test(self) -> None:
        mod.self_test()


class TestRunAll(unittest.TestCase):
    """run_all() returns a well-formed result dict."""

    def test_structure(self) -> None:
        result = mod.run_all()
        for key in ["bead_id", "section", "title", "verdict", "passed",
                     "failed", "total", "checks"]:
            self.assertIn(key, result)

    def test_bead_id(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-kiqr")

    def test_section(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["section"], "12")

    def test_verdict_pass(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS")

    def test_passed_lte_total(self) -> None:
        result = mod.run_all()
        self.assertLessEqual(result["passed"], result["total"])

    def test_failed_consistency(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["failed"], result["total"] - result["passed"])

    def test_check_names_unique(self) -> None:
        result = mod.run_all()
        names = [c["name"] for c in result["checks"]]
        self.assertEqual(len(names), len(set(names)), "Duplicate check names found")

    def test_all_passed_consistency(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["all_passed"], result["passed"] == result["total"])


class TestIndividualChecks(unittest.TestCase):
    """Each individual check function populates RESULTS correctly."""

    def _run_check(self, fn):
        mod.RESULTS.clear()
        fn()
        self.assertGreaterEqual(len(mod.RESULTS), 1)
        return mod.RESULTS[-1]

    def test_check_spec_exists(self) -> None:
        r = self._run_check(mod.check_spec_exists)
        self.assertEqual(r["name"], "spec_exists")
        self.assertTrue(r["passed"])

    def test_check_risk_policy_exists(self) -> None:
        r = self._run_check(mod.check_risk_policy_exists)
        self.assertEqual(r["name"], "risk_policy_exists")
        self.assertTrue(r["passed"])

    def test_check_risk_documented(self) -> None:
        r = self._run_check(mod.check_risk_documented)
        self.assertEqual(r["name"], "risk_documented")
        self.assertTrue(r["passed"])

    def test_check_replay_mechanism(self) -> None:
        r = self._run_check(mod.check_replay_mechanism)
        self.assertEqual(r["name"], "replay_mechanism")
        self.assertTrue(r["passed"])

    def test_check_degraded_mode(self) -> None:
        r = self._run_check(mod.check_degraded_mode)
        self.assertEqual(r["name"], "degraded_mode")
        self.assertTrue(r["passed"])

    def test_check_complexity_budget(self) -> None:
        r = self._run_check(mod.check_complexity_budget)
        self.assertEqual(r["name"], "complexity_budget")
        self.assertTrue(r["passed"])

    def test_check_countermeasures(self) -> None:
        r = self._run_check(mod.check_countermeasures)
        self.assertEqual(r["name"], "countermeasures")
        self.assertTrue(r["passed"])

    def test_check_event_codes(self) -> None:
        r = self._run_check(mod.check_event_codes)
        self.assertEqual(r["name"], "event_codes")
        self.assertTrue(r["passed"])

    def test_check_invariants(self) -> None:
        r = self._run_check(mod.check_invariants)
        self.assertEqual(r["name"], "invariants")
        self.assertTrue(r["passed"])

    def test_check_spec_keywords(self) -> None:
        r = self._run_check(mod.check_spec_keywords)
        self.assertEqual(r["name"], "spec_keywords")
        self.assertTrue(r["passed"])

    def test_check_threshold(self) -> None:
        r = self._run_check(mod.check_threshold)
        self.assertEqual(r["name"], "threshold")
        self.assertTrue(r["passed"])

    def test_check_alert_pipeline(self) -> None:
        r = self._run_check(mod.check_alert_pipeline)
        self.assertEqual(r["name"], "alert_pipeline")
        self.assertTrue(r["passed"])

    def test_check_escalation(self) -> None:
        r = self._run_check(mod.check_escalation)
        self.assertEqual(r["name"], "escalation")
        self.assertTrue(r["passed"])

    def test_check_evidence_requirements(self) -> None:
        r = self._run_check(mod.check_evidence_requirements)
        self.assertEqual(r["name"], "evidence_requirements")
        self.assertTrue(r["passed"])

    def test_check_monitoring(self) -> None:
        r = self._run_check(mod.check_monitoring)
        self.assertEqual(r["name"], "monitoring")
        self.assertTrue(r["passed"])

    def test_check_verification_evidence(self) -> None:
        r = self._run_check(mod.check_verification_evidence)
        self.assertEqual(r["name"], "verification_evidence")
        self.assertTrue(r["passed"])

    def test_check_verification_summary(self) -> None:
        r = self._run_check(mod.check_verification_summary)
        self.assertEqual(r["name"], "verification_summary")
        self.assertTrue(r["passed"])


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
        self.assertEqual(parsed["bead_id"], "bd-kiqr")

    def test_json_subprocess(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_trust_complexity.py"), "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-kiqr")
        self.assertEqual(parsed["verdict"], "PASS")


class TestConstants(unittest.TestCase):
    """Module-level constants are correct."""

    def test_event_codes_count(self) -> None:
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_invariants_count(self) -> None:
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_all_checks_count(self) -> None:
        self.assertEqual(len(mod.ALL_CHECKS), 17)

    def test_event_code_prefix(self) -> None:
        for code in mod.EVENT_CODES:
            self.assertTrue(code.startswith("RTC-"))

    def test_invariant_prefix(self) -> None:
        for inv in mod.INVARIANTS:
            self.assertTrue(inv.startswith("INV-RTC-"))


class TestSafeRel(unittest.TestCase):
    """_safe_rel handles both ROOT-based and non-ROOT paths."""

    def test_root_based_path(self) -> None:
        p = ROOT / "docs" / "test.md"
        result = mod._safe_rel(p)
        self.assertNotIn(str(ROOT), result)
        self.assertIn("docs", result)

    def test_non_root_path(self) -> None:
        p = Path("/tmp/fake/test.md")
        result = mod._safe_rel(p)
        self.assertEqual(result, str(p))


if __name__ == "__main__":
    unittest.main()
