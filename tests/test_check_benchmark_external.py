"""Unit tests for scripts/check_benchmark_external.py (bd-3e74)."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Import the verification script as a module
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "check_benchmark_external", ROOT / "scripts" / "check_benchmark_external.py"
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllStructure(unittest.TestCase):
    """run_all() returns a well-formed result dict."""

    def test_required_keys(self) -> None:
        result = mod.run_all()
        for key in ("bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"):
            self.assertIn(key, result, f"Missing key: {key}")

    def test_bead_id(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-3e74")

    def test_section(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["section"], "13")

    def test_total_equals_passed_plus_failed(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["passed"] + result["failed"], result["total"])

    def test_checks_is_list(self) -> None:
        result = mod.run_all()
        self.assertIsInstance(result["checks"], list)

    def test_check_entries_have_required_keys(self) -> None:
        result = mod.run_all()
        for check in result["checks"]:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)

    def test_all_check_names_unique(self) -> None:
        result = mod.run_all()
        names = [c["check"] for c in result["checks"]]
        self.assertEqual(len(names), len(set(names)), "Duplicate check names found")

    def test_verdict_is_pass_or_fail(self) -> None:
        result = mod.run_all()
        self.assertIn(result["verdict"], ("PASS", "FAIL"))

    def test_pass_values_are_bools(self) -> None:
        result = mod.run_all()
        for check in result["checks"]:
            self.assertIsInstance(check["pass"], bool)

    def test_total_matches_checks_length(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["total"], len(result["checks"]))


class TestSelfTest(unittest.TestCase):
    """The self_test() function must work correctly."""

    def test_self_test_returns_bool(self) -> None:
        result = mod.self_test()
        self.assertIsInstance(result, bool)

    def test_self_test_passes(self) -> None:
        result = mod.self_test()
        self.assertTrue(result)


class TestIndividualChecks(unittest.TestCase):
    """Individual check functions produce correct results."""

    def setUp(self) -> None:
        mod.RESULTS.clear()

    def tearDown(self) -> None:
        mod.RESULTS.clear()

    def test_check_spec_exists(self) -> None:
        mod.check_spec_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["check"], "spec_exists")
        if mod.SPEC.is_file():
            self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_policy_exists(self) -> None:
        mod.check_policy_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["check"], "policy_exists")
        if mod.POLICY.is_file():
            self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_spec_event_codes(self) -> None:
        mod.check_spec_event_codes()
        self.assertEqual(len(mod.RESULTS), 4)
        for i, code in enumerate(mod.EVENT_CODES):
            self.assertEqual(mod.RESULTS[i]["check"], f"spec_event_code:{code}")

    def test_check_spec_invariants(self) -> None:
        mod.check_spec_invariants()
        self.assertEqual(len(mod.RESULTS), 4)
        for i, inv in enumerate(mod.INVARIANTS):
            self.assertEqual(mod.RESULTS[i]["check"], f"spec_invariant:{inv}")

    def test_check_spec_adoption_tiers(self) -> None:
        mod.check_spec_adoption_tiers()
        self.assertEqual(len(mod.RESULTS), 5)
        for i, tier in enumerate(mod.ADOPTION_TIERS):
            self.assertEqual(mod.RESULTS[i]["check"], f"spec_tier:{tier}")

    def test_check_spec_quantitative_targets(self) -> None:
        mod.check_spec_quantitative_targets()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertTrue(r["check"].startswith("spec_target:"))

    def test_check_spec_metric_dimensions(self) -> None:
        mod.check_spec_metric_dimensions()
        self.assertEqual(len(mod.RESULTS), 6)
        for r in mod.RESULTS:
            self.assertTrue(r["check"].startswith("spec_dimension:"))

    def test_check_spec_gate_thresholds(self) -> None:
        mod.check_spec_gate_thresholds()
        self.assertEqual(len(mod.RESULTS), 2)
        self.assertEqual(mod.RESULTS[0]["check"], "spec_gate:alpha")
        self.assertEqual(mod.RESULTS[1]["check"], "spec_gate:beta")

    def test_check_spec_provenance(self) -> None:
        mod.check_spec_provenance()
        self.assertEqual(len(mod.RESULTS), 4)

    def test_check_spec_packaging_formats(self) -> None:
        mod.check_spec_packaging_formats()
        self.assertEqual(len(mod.RESULTS), 3)

    def test_check_spec_tracking_channels(self) -> None:
        mod.check_spec_tracking_channels()
        self.assertEqual(len(mod.RESULTS), 6)

    def test_check_spec_report_schema(self) -> None:
        mod.check_spec_report_schema()
        self.assertEqual(len(mod.RESULTS), 5)

    def test_check_policy_event_codes(self) -> None:
        mod.check_policy_event_codes()
        self.assertEqual(len(mod.RESULTS), 4)
        for i, code in enumerate(mod.EVENT_CODES):
            self.assertEqual(mod.RESULTS[i]["check"], f"policy_event_code:{code}")

    def test_check_policy_invariants(self) -> None:
        mod.check_policy_invariants()
        self.assertEqual(len(mod.RESULTS), 4)
        for i, inv in enumerate(mod.INVARIANTS):
            self.assertEqual(mod.RESULTS[i]["check"], f"policy_invariant:{inv}")

    def test_check_policy_adoption_tiers(self) -> None:
        mod.check_policy_adoption_tiers()
        self.assertEqual(len(mod.RESULTS), 5)

    def test_check_policy_metric_definitions(self) -> None:
        mod.check_policy_metric_definitions()
        self.assertEqual(len(mod.RESULTS), 6)

    def test_check_policy_sybil_defense(self) -> None:
        mod.check_policy_sybil_defense()
        self.assertEqual(len(mod.RESULTS), 3)

    def test_check_policy_ci_integration(self) -> None:
        mod.check_policy_ci_integration()
        self.assertEqual(len(mod.RESULTS), 2)

    def test_check_policy_escalation(self) -> None:
        mod.check_policy_escalation()
        self.assertEqual(len(mod.RESULTS), 3)

    def test_check_policy_provenance(self) -> None:
        mod.check_policy_provenance()
        self.assertEqual(len(mod.RESULTS), 4)

    def test_check_policy_risk_impact(self) -> None:
        mod.check_policy_risk_impact()
        self.assertEqual(len(mod.RESULTS), 2)

    def test_check_policy_monitoring(self) -> None:
        mod.check_policy_monitoring()
        self.assertEqual(len(mod.RESULTS), 3)

    def test_check_evidence_artifacts(self) -> None:
        mod.check_evidence_artifacts()
        self.assertEqual(len(mod.RESULTS), 2)


class TestMissingFileDetection(unittest.TestCase):
    """When files are missing, checks fail gracefully."""

    def setUp(self) -> None:
        mod.RESULTS.clear()
        self._orig_spec = mod.SPEC
        self._orig_policy = mod.POLICY

    def tearDown(self) -> None:
        mod.SPEC = self._orig_spec
        mod.POLICY = self._orig_policy
        mod.RESULTS.clear()

    def test_missing_spec_event_codes(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_event_codes()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])
        self.assertIn("spec missing", mod.RESULTS[0]["detail"])

    def test_missing_spec_invariants(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_invariants()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_spec_adoption_tiers(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_adoption_tiers()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_spec_quantitative_targets(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_quantitative_targets()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_spec_metric_dimensions(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_metric_dimensions()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_spec_gate_thresholds(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_gate_thresholds()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_spec_provenance(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_provenance()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_spec_packaging_formats(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_packaging_formats()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_spec_tracking_channels(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_tracking_channels()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_spec_report_schema(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_report_schema()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_spec_cryptographic(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_exists()
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_event_codes(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_event_codes()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_invariants(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_invariants()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_adoption_tiers(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_adoption_tiers()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_metric_definitions(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_metric_definitions()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_sybil_defense(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_sybil_defense()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_ci_integration(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_ci_integration()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_escalation(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_escalation()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_provenance(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_provenance()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_risk_impact(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_risk_impact()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_missing_policy_monitoring(self) -> None:
        mod.POLICY = Path("/nonexistent/policy.md")
        mod.check_policy_monitoring()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])


class TestValidateExternalMetrics(unittest.TestCase):
    """validate_external_metrics() validates metric dicts."""

    def test_valid_metrics(self) -> None:
        metrics = {
            "external_project_adoption": 5,
            "external_validation_parties": 3,
            "external_citations": 2,
            "packaging_formats": 1,
            "getting_started_time": 10,
            "tracking_channels": 3,
        }
        errors = mod.validate_external_metrics(metrics)
        self.assertEqual(errors, [])

    def test_missing_key(self) -> None:
        metrics = {"external_project_adoption": 5}
        errors = mod.validate_external_metrics(metrics)
        self.assertTrue(len(errors) > 0)
        missing_keys = [e for e in errors if "missing metric" in e]
        self.assertTrue(len(missing_keys) > 0)

    def test_non_numeric_value(self) -> None:
        metrics = {
            "external_project_adoption": "not_a_number",
            "external_validation_parties": 3,
            "external_citations": 2,
            "packaging_formats": 1,
            "getting_started_time": 10,
            "tracking_channels": 3,
        }
        errors = mod.validate_external_metrics(metrics)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any("non-numeric" in e for e in errors))

    def test_empty_dict(self) -> None:
        errors = mod.validate_external_metrics({})
        self.assertEqual(len(errors), 6)  # all 6 keys missing

    def test_float_values_accepted(self) -> None:
        metrics = {
            "external_project_adoption": 5.0,
            "external_validation_parties": 3.0,
            "external_citations": 2.0,
            "packaging_formats": 1.0,
            "getting_started_time": 10.5,
            "tracking_channels": 3.0,
        }
        errors = mod.validate_external_metrics(metrics)
        self.assertEqual(errors, [])


class TestMetricsToTier(unittest.TestCase):
    """metrics_to_tier() maps metrics to correct adoption tiers."""

    def test_u0_no_usage(self) -> None:
        metrics = {
            "external_project_adoption": 0,
            "external_validation_parties": 0,
            "external_citations": 0,
        }
        self.assertEqual(mod.metrics_to_tier(metrics), "U0")

    def test_u1_one_user(self) -> None:
        metrics = {
            "external_project_adoption": 1,
            "external_validation_parties": 0,
            "external_citations": 0,
        }
        self.assertEqual(mod.metrics_to_tier(metrics), "U1")

    def test_u2_validation_parties(self) -> None:
        metrics = {
            "external_project_adoption": 0,
            "external_validation_parties": 2,
            "external_citations": 0,
        }
        self.assertEqual(mod.metrics_to_tier(metrics), "U2")

    def test_u3_three_adoptions(self) -> None:
        metrics = {
            "external_project_adoption": 3,
            "external_validation_parties": 0,
            "external_citations": 0,
        }
        self.assertEqual(mod.metrics_to_tier(metrics), "U3")

    def test_u4_all_targets(self) -> None:
        metrics = {
            "external_project_adoption": 3,
            "external_validation_parties": 2,
            "external_citations": 1,
        }
        self.assertEqual(mod.metrics_to_tier(metrics), "U4")

    def test_empty_dict_returns_u0(self) -> None:
        self.assertEqual(mod.metrics_to_tier({}), "U0")

    def test_u2_with_adoption_below_3(self) -> None:
        metrics = {
            "external_project_adoption": 2,
            "external_validation_parties": 2,
            "external_citations": 0,
        }
        self.assertEqual(mod.metrics_to_tier(metrics), "U2")

    def test_u3_takes_priority_over_u2(self) -> None:
        metrics = {
            "external_project_adoption": 3,
            "external_validation_parties": 2,
            "external_citations": 0,
        }
        # Has both U2 and U3 criteria, but no citations -> U3 (not U4)
        self.assertEqual(mod.metrics_to_tier(metrics), "U3")


class TestConstants(unittest.TestCase):
    """Module constants are correctly defined."""

    def test_event_codes(self) -> None:
        self.assertEqual(mod.EVENT_CODES, ["BVE-001", "BVE-002", "BVE-003", "BVE-004"])

    def test_invariants(self) -> None:
        self.assertEqual(mod.INVARIANTS, ["INV-BVE-PACKAGE", "INV-BVE-GUIDE", "INV-BVE-TRACK", "INV-BVE-REPORT"])

    def test_adoption_tiers(self) -> None:
        self.assertEqual(mod.ADOPTION_TIERS, ["U0", "U1", "U2", "U3", "U4"])

    def test_metric_targets(self) -> None:
        self.assertIn("external_project_adoption", mod.METRIC_TARGETS)
        self.assertIn("external_validation_parties", mod.METRIC_TARGETS)
        self.assertIn("external_citations", mod.METRIC_TARGETS)
        self.assertIn("packaging_formats", mod.METRIC_TARGETS)
        self.assertIn("getting_started_time", mod.METRIC_TARGETS)
        self.assertIn("tracking_channels", mod.METRIC_TARGETS)
        self.assertEqual(len(mod.METRIC_TARGETS), 6)

    def test_all_checks_list(self) -> None:
        self.assertIsInstance(mod.ALL_CHECKS, list)
        self.assertTrue(len(mod.ALL_CHECKS) > 0)
        for fn in mod.ALL_CHECKS:
            self.assertTrue(callable(fn))

    def test_spec_path(self) -> None:
        self.assertTrue(str(mod.SPEC).endswith("docs/specs/section_13/bd-3e74_contract.md"))

    def test_policy_path(self) -> None:
        self.assertTrue(str(mod.POLICY).endswith("docs/policy/benchmark_verifier_external_usage.md"))


class TestJsonOutput(unittest.TestCase):
    """JSON output must be valid and contain required keys."""

    def test_json_serializable(self) -> None:
        result = mod.run_all()
        text = json.dumps(result, indent=2)
        parsed = json.loads(text)
        self.assertEqual(parsed["bead_id"], "bd-3e74")
        self.assertIsInstance(parsed["checks"], list)

    def test_json_round_trip(self) -> None:
        result = mod.run_all()
        text = json.dumps(result)
        parsed = json.loads(text)
        self.assertEqual(parsed["total"], result["total"])
        self.assertEqual(parsed["passed"], result["passed"])
        self.assertEqual(parsed["failed"], result["failed"])
        self.assertEqual(len(parsed["checks"]), len(result["checks"]))


class TestSafeRel(unittest.TestCase):
    """_safe_rel() handles paths correctly."""

    def test_path_under_root(self) -> None:
        p = mod.ROOT / "docs" / "test.md"
        self.assertEqual(mod._safe_rel(p), "docs/test.md")

    def test_path_outside_root(self) -> None:
        p = Path("/tmp/outside/test.md")
        self.assertEqual(mod._safe_rel(p), "/tmp/outside/test.md")

    def test_root_itself(self) -> None:
        result = mod._safe_rel(mod.ROOT)
        self.assertEqual(result, ".")


class TestCheckHelper(unittest.TestCase):
    """_check() accumulator works correctly."""

    def setUp(self) -> None:
        mod.RESULTS.clear()

    def tearDown(self) -> None:
        mod.RESULTS.clear()

    def test_check_appends(self) -> None:
        mod._check("t1", True, "ok")
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertTrue(mod.RESULTS[0]["pass"])

    def test_check_fail(self) -> None:
        mod._check("t2", False, "bad")
        self.assertFalse(mod.RESULTS[0]["pass"])

    def test_check_returns_entry(self) -> None:
        entry = mod._check("t3", True, "detail")
        self.assertEqual(entry["check"], "t3")
        self.assertTrue(entry["pass"])
        self.assertEqual(entry["detail"], "detail")

    def test_check_default_detail(self) -> None:
        entry = mod._check("t4", True)
        self.assertEqual(entry["detail"], "found")
        mod.RESULTS.clear()
        entry = mod._check("t5", False)
        self.assertEqual(entry["detail"], "NOT FOUND")


class TestOverallPass(unittest.TestCase):
    """When all deliverables exist, verdict should be PASS."""

    def test_overall_pass(self) -> None:
        result = mod.run_all()
        failures = [c for c in result["checks"] if not c["pass"]]
        if failures:
            names = [f["check"] for f in failures]
            self.fail(f"Checks failed: {names}")
        self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
