"""Unit tests for scripts/check_expected_loss.py."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_expected_loss as mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_valid_elm() -> dict:
    """Return a fully valid expected-loss model object."""
    return {
        "scenarios": [
            {
                "name": "Full outage",
                "probability": 0.05,
                "impact_value": 500000,
                "impact_unit": "dollars",
                "mitigation": "Redundant failover cluster",
            },
            {
                "name": "Data corruption",
                "probability": 0.02,
                "impact_value": 1000000,
                "impact_unit": "dollars",
                "mitigation": "Immutable backup with PITR",
            },
            {
                "name": "Partial degradation",
                "probability": 0.15,
                "impact_value": 50000,
                "impact_unit": "dollars",
                "mitigation": "Circuit breaker pattern",
            },
        ],
        "aggregate_expected_loss": 52500.0,
        "confidence_interval": {
            "lower": 30000.0,
            "upper": 80000.0,
            "confidence_level": 0.95,
        },
        "loss_category": "major",
    }


def _make_negligible_elm() -> dict:
    """Return a valid expected-loss model with negligible category."""
    return {
        "scenarios": [
            {"name": "UI glitch", "probability": 0.1, "impact_value": 100, "impact_unit": "hours", "mitigation": "Hotfix"},
            {"name": "Stale cache", "probability": 0.2, "impact_value": 50, "impact_unit": "hours", "mitigation": "Invalidation"},
            {"name": "Log noise", "probability": 0.3, "impact_value": 10, "impact_unit": "hours", "mitigation": "Filter"},
        ],
        "aggregate_expected_loss": 23.0,
        "confidence_interval": {"lower": 10.0, "upper": 50.0, "confidence_level": 0.90},
        "loss_category": "negligible",
    }


# ---------------------------------------------------------------------------
# TestSelfTest
# ---------------------------------------------------------------------------

class TestSelfTest(unittest.TestCase):
    def test_self_test_returns_tuple(self):
        result = mod.self_test()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_self_test_passes(self):
        ok, msg = mod.self_test()
        self.assertTrue(ok, msg)

    def test_self_test_message_is_string(self):
        ok, msg = mod.self_test()
        self.assertIsInstance(msg, str)
        self.assertIn("self_test", msg)


# ---------------------------------------------------------------------------
# TestRunAll
# ---------------------------------------------------------------------------

class TestRunAll(unittest.TestCase):
    def test_structure(self):
        result = mod.run_all()
        for key in ["bead_id", "section", "title", "status", "passed", "total", "all_passed", "checks"]:
            self.assertIn(key, result)

    def test_bead_id(self):
        self.assertEqual(mod.run_all()["bead_id"], "bd-2fpj")

    def test_section(self):
        self.assertEqual(mod.run_all()["section"], "11")

    def test_title(self):
        self.assertIn("expected-loss", mod.run_all()["title"])

    def test_all_passed(self):
        self.assertTrue(mod.run_all()["all_passed"])

    def test_status_pass(self):
        self.assertEqual(mod.run_all()["status"], "pass")

    def test_check_names_unique(self):
        result = mod.run_all()
        names = [c["name"] for c in result["checks"]]
        self.assertEqual(len(names), len(set(names)))

    def test_passed_equals_total(self):
        result = mod.run_all()
        self.assertEqual(result["passed"], result["total"])


# ---------------------------------------------------------------------------
# TestIndividualChecks
# ---------------------------------------------------------------------------

class TestIndividualChecks(unittest.TestCase):
    def _run(self, fn):
        mod.RESULTS.clear()
        fn()
        return mod.RESULTS[-1]

    def test_spec_exists(self):
        self.assertTrue(self._run(mod.check_spec_exists)["passed"])

    def test_contract_field(self):
        self.assertTrue(self._run(mod.check_contract_field)["passed"])

    def test_scenarios_schema(self):
        self.assertTrue(self._run(mod.check_scenarios_schema)["passed"])

    def test_loss_categories(self):
        self.assertTrue(self._run(mod.check_loss_categories)["passed"])

    def test_category_thresholds(self):
        self.assertTrue(self._run(mod.check_category_thresholds)["passed"])

    def test_aggregate_formula(self):
        self.assertTrue(self._run(mod.check_aggregate_formula)["passed"])

    def test_confidence_interval(self):
        self.assertTrue(self._run(mod.check_confidence_interval)["passed"])

    def test_event_codes(self):
        self.assertTrue(self._run(mod.check_event_codes)["passed"])

    def test_invariants(self):
        self.assertTrue(self._run(mod.check_invariants)["passed"])

    def test_acceptance_criteria(self):
        self.assertTrue(self._run(mod.check_acceptance_criteria)["passed"])

    def test_enforcement(self):
        self.assertTrue(self._run(mod.check_enforcement)["passed"])

    def test_evidence(self):
        self.assertTrue(self._run(mod.check_verification_evidence)["passed"])

    def test_summary(self):
        self.assertTrue(self._run(mod.check_verification_summary)["passed"])


# ---------------------------------------------------------------------------
# TestValidateElm
# ---------------------------------------------------------------------------

class TestValidateElm(unittest.TestCase):
    def test_valid_major(self):
        elm = _make_valid_elm()
        results = mod.validate_elm_object(elm)
        for r in results:
            self.assertTrue(r["passed"], f"Failed: {r['name']}: {r['detail']}")

    def test_valid_negligible(self):
        elm = _make_negligible_elm()
        results = mod.validate_elm_object(elm)
        for r in results:
            self.assertTrue(r["passed"], f"Failed: {r['name']}: {r['detail']}")

    def test_too_few_scenarios(self):
        elm = _make_valid_elm()
        elm["scenarios"] = elm["scenarios"][:2]
        elm["aggregate_expected_loss"] = mod.compute_aggregate(elm["scenarios"])
        elm["loss_category"] = mod.classify_loss(elm["aggregate_expected_loss"])
        results = mod.validate_elm_object(elm)
        count_check = [r for r in results if r["name"] == "scenarios_min_count"][0]
        self.assertFalse(count_check["passed"])

    def test_probability_out_of_range(self):
        elm = _make_valid_elm()
        elm["scenarios"][0]["probability"] = 1.5
        results = mod.validate_elm_object(elm)
        schema_check = [r for r in results if r["name"] == "scenarios_schema_valid"][0]
        self.assertFalse(schema_check["passed"])

    def test_negative_impact_value(self):
        elm = _make_valid_elm()
        elm["scenarios"][1]["impact_value"] = -100
        results = mod.validate_elm_object(elm)
        schema_check = [r for r in results if r["name"] == "scenarios_schema_valid"][0]
        self.assertFalse(schema_check["passed"])

    def test_invalid_impact_unit(self):
        elm = _make_valid_elm()
        elm["scenarios"][2]["impact_unit"] = "bananas"
        results = mod.validate_elm_object(elm)
        schema_check = [r for r in results if r["name"] == "scenarios_schema_valid"][0]
        self.assertFalse(schema_check["passed"])

    def test_empty_mitigation(self):
        elm = _make_valid_elm()
        elm["scenarios"][0]["mitigation"] = ""
        results = mod.validate_elm_object(elm)
        schema_check = [r for r in results if r["name"] == "scenarios_schema_valid"][0]
        self.assertFalse(schema_check["passed"])

    def test_aggregate_mismatch(self):
        elm = _make_valid_elm()
        elm["aggregate_expected_loss"] = 99999.0
        results = mod.validate_elm_object(elm)
        agg_check = [r for r in results if r["name"] == "aggregate_formula_correct"][0]
        self.assertFalse(agg_check["passed"])

    def test_category_mismatch(self):
        elm = _make_valid_elm()
        elm["loss_category"] = "negligible"  # should be "major"
        results = mod.validate_elm_object(elm)
        cat_check = [r for r in results if r["name"] == "category_matches_thresholds"][0]
        self.assertFalse(cat_check["passed"])

    def test_confidence_bounds_inverted(self):
        elm = _make_valid_elm()
        elm["confidence_interval"]["lower"] = 90000.0
        elm["confidence_interval"]["upper"] = 10000.0
        results = mod.validate_elm_object(elm)
        bounds_check = [r for r in results if r["name"] == "confidence_bounds_valid"][0]
        self.assertFalse(bounds_check["passed"])

    def test_confidence_level_out_of_range(self):
        elm = _make_valid_elm()
        elm["confidence_interval"]["confidence_level"] = 1.0
        results = mod.validate_elm_object(elm)
        cl_check = [r for r in results if r["name"] == "confidence_level_valid"][0]
        self.assertFalse(cl_check["passed"])

    def test_aggregate_outside_confidence(self):
        elm = _make_valid_elm()
        elm["confidence_interval"]["lower"] = 60000.0
        elm["confidence_interval"]["upper"] = 80000.0
        results = mod.validate_elm_object(elm)
        agg_ci = [r for r in results if r["name"] == "aggregate_within_confidence"][0]
        self.assertFalse(agg_ci["passed"])

    def test_empty_scenario_name(self):
        elm = _make_valid_elm()
        elm["scenarios"][0]["name"] = ""
        results = mod.validate_elm_object(elm)
        schema_check = [r for r in results if r["name"] == "scenarios_schema_valid"][0]
        self.assertFalse(schema_check["passed"])


# ---------------------------------------------------------------------------
# TestConstants
# ---------------------------------------------------------------------------

class TestConstants(unittest.TestCase):
    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_event_codes_prefix(self):
        for code in mod.EVENT_CODES:
            self.assertTrue(code.startswith("CONTRACT_ELM_"))

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_invariants_prefix(self):
        for inv in mod.INVARIANTS:
            self.assertTrue(inv.startswith("INV-ELM-"))

    def test_loss_categories_count(self):
        self.assertEqual(len(mod.LOSS_CATEGORIES), 5)

    def test_loss_categories_values(self):
        self.assertEqual(mod.LOSS_CATEGORIES, ["negligible", "minor", "moderate", "major", "catastrophic"])

    def test_all_checks_count(self):
        self.assertEqual(len(mod.ALL_CHECKS), 13)

    def test_valid_impact_units(self):
        self.assertEqual(mod.VALID_IMPACT_UNITS, ["dollars", "hours", "severity_units"])

    def test_category_thresholds_dict(self):
        self.assertIn("negligible", mod.CATEGORY_THRESHOLDS)
        self.assertIn("catastrophic", mod.CATEGORY_THRESHOLDS)
        self.assertEqual(mod.CATEGORY_THRESHOLDS["negligible"], (0, 100))
        self.assertEqual(mod.CATEGORY_THRESHOLDS["catastrophic"], (100_000, float("inf")))


# ---------------------------------------------------------------------------
# TestClassifyLoss
# ---------------------------------------------------------------------------

class TestClassifyLoss(unittest.TestCase):
    def test_negligible(self):
        self.assertEqual(mod.classify_loss(0), "negligible")
        self.assertEqual(mod.classify_loss(99.99), "negligible")

    def test_minor(self):
        self.assertEqual(mod.classify_loss(100), "minor")
        self.assertEqual(mod.classify_loss(999.99), "minor")

    def test_moderate(self):
        self.assertEqual(mod.classify_loss(1000), "moderate")
        self.assertEqual(mod.classify_loss(9999.99), "moderate")

    def test_major(self):
        self.assertEqual(mod.classify_loss(10000), "major")
        self.assertEqual(mod.classify_loss(99999.99), "major")

    def test_catastrophic(self):
        self.assertEqual(mod.classify_loss(100000), "catastrophic")
        self.assertEqual(mod.classify_loss(1000000), "catastrophic")


# ---------------------------------------------------------------------------
# TestComputeAggregate
# ---------------------------------------------------------------------------

class TestComputeAggregate(unittest.TestCase):
    def test_basic(self):
        scenarios = [
            {"probability": 0.1, "impact_value": 1000},
            {"probability": 0.2, "impact_value": 2000},
            {"probability": 0.3, "impact_value": 3000},
        ]
        self.assertAlmostEqual(mod.compute_aggregate(scenarios), 1400.0)

    def test_empty(self):
        self.assertEqual(mod.compute_aggregate([]), 0)


# ---------------------------------------------------------------------------
# TestJsonOutput
# ---------------------------------------------------------------------------

class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-2fpj")

    def test_json_round_trip(self):
        result = mod.run_all()
        text = json.dumps(result, indent=2)
        parsed = json.loads(text)
        self.assertEqual(parsed["section"], "11")
        self.assertEqual(parsed["all_passed"], True)


if __name__ == "__main__":
    unittest.main()
