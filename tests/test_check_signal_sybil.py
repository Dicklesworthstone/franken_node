"""Unit tests for scripts/check_signal_sybil.py (bd-13yn)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "check_signal_sybil", ROOT / "scripts" / "check_signal_sybil.py"
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllStructure(unittest.TestCase):
    """run_all() returns a well-formed result dict."""

    def test_returns_dict(self) -> None:
        result = mod.run_all()
        self.assertIsInstance(result, dict)

    def test_bead_id(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-13yn")

    def test_section(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["section"], "12")

    def test_title(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["title"], "signal poisoning and Sybil risk control")

    def test_verdict_is_string(self) -> None:
        result = mod.run_all()
        self.assertIn(result["verdict"], ("PASS", "FAIL"))

    def test_total_positive(self) -> None:
        result = mod.run_all()
        self.assertGreater(result["total"], 0)

    def test_passed_lte_total(self) -> None:
        result = mod.run_all()
        self.assertLessEqual(result["passed"], result["total"])

    def test_failed_consistency(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["failed"], result["total"] - result["passed"])

    def test_checks_is_list(self) -> None:
        result = mod.run_all()
        self.assertIsInstance(result["checks"], list)
        self.assertEqual(len(result["checks"]), result["total"])

    def test_verdict_consistency(self) -> None:
        result = mod.run_all()
        if result["failed"] == 0:
            self.assertEqual(result["verdict"], "PASS")
        else:
            self.assertEqual(result["verdict"], "FAIL")

    def test_check_names_unique(self) -> None:
        result = mod.run_all()
        names = [c["check"] for c in result["checks"]]
        self.assertEqual(len(names), len(set(names)), "Duplicate check names found")

    def test_check_entry_format(self) -> None:
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)
            self.assertIsInstance(c["check"], str)
            self.assertIsInstance(c["pass"], bool)
            self.assertIsInstance(c["detail"], str)


class TestSelfTest(unittest.TestCase):
    """self_test() returns bool and does not raise."""

    def test_self_test_returns_bool(self) -> None:
        result = mod.self_test()
        self.assertIsInstance(result, bool)

    def test_self_test_consistent_with_run_all(self) -> None:
        report = mod.run_all()
        expected = report["failed"] == 0
        result = mod.self_test()
        self.assertEqual(result, expected)


class TestIndividualChecks(unittest.TestCase):
    """Each individual check function populates RESULTS correctly."""

    def setUp(self) -> None:
        mod.RESULTS = []

    def test_check_spec_exists(self) -> None:
        mod.check_spec_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["check"], "spec_exists")
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_policy_exists(self) -> None:
        mod.check_policy_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["check"], "policy_exists")
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_spec_bead_id(self) -> None:
        mod.check_spec_bead_id()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["check"], "spec_bead_id")
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_spec_section(self) -> None:
        mod.check_spec_section()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["check"], "spec_section_12")
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_spec_event_codes(self) -> None:
        mod.check_spec_event_codes()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertTrue(r["pass"], f"{r['check']} should pass")

    def test_check_spec_invariants(self) -> None:
        mod.check_spec_invariants()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertTrue(r["pass"], f"{r['check']} should pass")

    def test_check_spec_error_codes(self) -> None:
        mod.check_spec_error_codes()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertTrue(r["pass"], f"{r['check']} should pass")

    def test_check_spec_thresholds(self) -> None:
        mod.check_spec_thresholds()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_spec_countermeasures(self) -> None:
        mod.check_spec_countermeasures()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_spec_acceptance_criteria(self) -> None:
        mod.check_spec_acceptance_criteria()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_spec_test_scenarios(self) -> None:
        mod.check_spec_test_scenarios()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_policy_risk_description(self) -> None:
        mod.check_policy_risk_description()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_policy_impact(self) -> None:
        mod.check_policy_impact()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_policy_likelihood(self) -> None:
        mod.check_policy_likelihood()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_policy_countermeasures(self) -> None:
        mod.check_policy_countermeasures()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_policy_escalation(self) -> None:
        mod.check_policy_escalation()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_policy_evidence_requirements(self) -> None:
        mod.check_policy_evidence_requirements()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_policy_thresholds(self) -> None:
        mod.check_policy_thresholds()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_policy_invariants(self) -> None:
        mod.check_policy_invariants()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertTrue(r["pass"], f"{r['check']} should pass")

    def test_check_policy_event_codes(self) -> None:
        mod.check_policy_event_codes()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertTrue(r["pass"], f"{r['check']} should pass")

    def test_check_verification_evidence(self) -> None:
        mod.check_verification_evidence()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["check"], "verification_evidence")
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_verification_summary(self) -> None:
        mod.check_verification_summary()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["check"], "verification_summary")
        self.assertTrue(mod.RESULTS[0]["pass"])


class TestMissingFileDetection(unittest.TestCase):
    """Checks correctly report missing files."""

    def setUp(self) -> None:
        mod.RESULTS = []
        self._orig_spec = mod.SPEC
        self._orig_policy = mod.POLICY

    def tearDown(self) -> None:
        mod.SPEC = self._orig_spec
        mod.POLICY = self._orig_policy
        mod.RESULTS = []

    def test_missing_spec_detected(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])
        self.assertIn("MISSING", mod.RESULTS[0]["detail"])

    def test_missing_policy_detected(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])
        self.assertIn("MISSING", mod.RESULTS[0]["detail"])

    def test_missing_spec_bead_id(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_bead_id()
        self.assertFalse(mod.RESULTS[0]["pass"])
        self.assertIn("spec file missing", mod.RESULTS[0]["detail"])

    def test_missing_spec_section(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_section()
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_spec_event_codes(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_event_codes()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertFalse(r["pass"])

    def test_missing_spec_invariants(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_invariants()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertFalse(r["pass"])

    def test_missing_spec_error_codes(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_error_codes()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertFalse(r["pass"])

    def test_missing_policy_risk_description(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_risk_description()
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_impact(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_impact()
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_countermeasures(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_countermeasures()
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_escalation(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_escalation()
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_invariants(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_invariants()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertFalse(r["pass"])

    def test_missing_policy_event_codes(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_event_codes()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertFalse(r["pass"])


class TestValidateSignalProvenance(unittest.TestCase):
    """validate_signal_provenance() checks provenance coverage."""

    def setUp(self) -> None:
        mod.RESULTS = []
        self._orig_policy = mod.POLICY

    def tearDown(self) -> None:
        mod.POLICY = self._orig_policy
        mod.RESULTS = []

    def test_passes_with_real_policy(self) -> None:
        mod.validate_signal_provenance()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_fails_with_missing_file(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.validate_signal_provenance()
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_check_name(self) -> None:
        mod.validate_signal_provenance()
        self.assertEqual(mod.RESULTS[0]["check"], "signal_provenance_coverage")


class TestValidateSybilResistance(unittest.TestCase):
    """validate_sybil_resistance() checks Sybil mechanisms."""

    def setUp(self) -> None:
        mod.RESULTS = []
        self._orig_policy = mod.POLICY

    def tearDown(self) -> None:
        mod.POLICY = self._orig_policy
        mod.RESULTS = []

    def test_passes_with_real_policy(self) -> None:
        mod.validate_sybil_resistance()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_fails_with_missing_file(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.validate_sybil_resistance()
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_check_name(self) -> None:
        mod.validate_sybil_resistance()
        self.assertEqual(mod.RESULTS[0]["check"], "sybil_resistance_mechanisms")


class TestConstants(unittest.TestCase):
    """Module-level constants are correct."""

    def test_event_codes(self) -> None:
        self.assertEqual(
            mod.EVENT_CODES, ["SPS-001", "SPS-002", "SPS-003", "SPS-004"]
        )

    def test_invariants(self) -> None:
        self.assertEqual(
            mod.INVARIANTS,
            [
                "INV-SPS-AGGREGATION",
                "INV-SPS-STAKE",
                "INV-SPS-SYBIL",
                "INV-SPS-ADVERSARIAL",
            ],
        )

    def test_error_codes(self) -> None:
        self.assertEqual(
            mod.ERROR_CODES,
            [
                "ERR_SPS_POISONED_SIGNAL",
                "ERR_SPS_SYBIL_DETECTED",
                "ERR_SPS_INSUFFICIENT_STAKE",
                "ERR_SPS_AGGREGATION_FAILED",
            ],
        )

    def test_root_is_directory(self) -> None:
        self.assertTrue(mod.ROOT.is_dir())

    def test_all_checks_list(self) -> None:
        self.assertIsInstance(mod.ALL_CHECKS, list)
        self.assertGreater(len(mod.ALL_CHECKS), 0)
        for fn in mod.ALL_CHECKS:
            self.assertTrue(callable(fn))


class TestJsonOutput(unittest.TestCase):
    """--json flag produces valid JSON."""

    def test_json_serializable(self) -> None:
        result = mod.run_all()
        output = json.dumps(result, indent=2)
        parsed = json.loads(output)
        self.assertEqual(parsed["bead_id"], "bd-13yn")
        self.assertEqual(parsed["section"], "12")
        self.assertIn("checks", parsed)
        self.assertIsInstance(parsed["checks"], list)

    def test_json_check_format(self) -> None:
        result = mod.run_all()
        output = json.dumps(result, indent=2)
        parsed = json.loads(output)
        for c in parsed["checks"]:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)


class TestSafeRel(unittest.TestCase):
    """_safe_rel() handles paths correctly."""

    def test_path_within_root(self) -> None:
        p = mod.ROOT / "docs" / "specs" / "test.md"
        result = mod._safe_rel(p)
        self.assertEqual(result, "docs/specs/test.md")

    def test_path_outside_root(self) -> None:
        p = Path("/tmp/some/other/path.md")
        result = mod._safe_rel(p)
        self.assertEqual(result, "/tmp/some/other/path.md")

    def test_root_itself(self) -> None:
        result = mod._safe_rel(mod.ROOT)
        self.assertEqual(result, ".")

    def test_deeply_nested_path(self) -> None:
        p = mod.ROOT / "a" / "b" / "c" / "d.txt"
        result = mod._safe_rel(p)
        self.assertEqual(result, "a/b/c/d.txt")


class TestCheckHelper(unittest.TestCase):
    """_check() helper function works correctly."""

    def setUp(self) -> None:
        mod.RESULTS = []

    def tearDown(self) -> None:
        mod.RESULTS = []

    def test_check_pass(self) -> None:
        entry = mod._check("test_pass", True, "it passed")
        self.assertEqual(entry["check"], "test_pass")
        self.assertTrue(entry["pass"])
        self.assertEqual(entry["detail"], "it passed")
        self.assertEqual(len(mod.RESULTS), 1)

    def test_check_fail(self) -> None:
        entry = mod._check("test_fail", False, "it failed")
        self.assertFalse(entry["pass"])
        self.assertEqual(entry["detail"], "it failed")

    def test_check_default_detail_pass(self) -> None:
        entry = mod._check("test_default", True)
        self.assertEqual(entry["detail"], "found")

    def test_check_default_detail_fail(self) -> None:
        entry = mod._check("test_default", False)
        self.assertEqual(entry["detail"], "NOT FOUND")

    def test_check_appends_to_results(self) -> None:
        mod._check("a", True, "ok")
        mod._check("b", False, "nope")
        self.assertEqual(len(mod.RESULTS), 2)

    def test_check_returns_entry(self) -> None:
        entry = mod._check("ret", True, "ok")
        self.assertIs(entry, mod.RESULTS[-1])


class TestRunAllIdempotent(unittest.TestCase):
    """run_all() resets RESULTS each time."""

    def test_idempotent(self) -> None:
        r1 = mod.run_all()
        r2 = mod.run_all()
        self.assertEqual(r1["total"], r2["total"])
        self.assertEqual(r1["passed"], r2["passed"])
        self.assertEqual(len(r1["checks"]), len(r2["checks"]))


if __name__ == "__main__":
    unittest.main()
