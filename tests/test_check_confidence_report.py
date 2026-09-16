#!/usr/bin/env python3
"""Unit tests for heuristic scores and observation-backed migration decisions."""

import copy
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import migration_confidence_report as report


class TestComputeConfidence(unittest.TestCase):
    def test_perfect_inputs_high_score(self):
        self.assertGreaterEqual(report.compute_confidence(0, 1, 1, 1)["confidence_score"], 80)

    def test_worst_inputs_low_score(self):
        self.assertLessEqual(report.compute_confidence(100, 0, 0, 0)["confidence_score"], 20)

    def test_score_bounded(self):
        self.assertTrue(0 <= report.compute_confidence(0, 1, 1, 1)["confidence_score"] <= 100)

    def test_uncertainty_band_present(self):
        self.assertGreaterEqual(report.compute_confidence(50, .5, .5, .5)["uncertainty_band"]["width"], 0)

    def test_uncertainty_wider_with_less_data(self):
        good = report.compute_confidence(50, .9, .9, .9)
        bad = report.compute_confidence(50, .1, .1, .1)
        self.assertGreater(bad["uncertainty_band"]["width"], good["uncertainty_band"]["width"])

    def test_components_sum_to_score(self):
        result = report.compute_confidence(30, .8, .7, .9)
        self.assertAlmostEqual(result["confidence_score"], sum(result["components"].values()), places=0)

    def test_rejects_nonfinite_out_of_range_and_boolean_inputs(self):
        for index in range(4):
            for value in (float("nan"), float("inf"), -1, True, "1", 101):
                with self.subTest(index=index, value=value):
                    values = [0, 1, 1, 1]
                    values[index] = value
                    with self.assertRaises(ValueError):
                        report.compute_confidence(*values)

    def test_score_and_interval_do_not_claim_statistical_confidence(self):
        result = report.compute_confidence(0, 1, 1, 1)
        self.assertEqual(result["score_kind"], "heuristic_not_probability")
        self.assertEqual(result["uncertainty_band"]["kind"], "heuristic_not_statistical_interval")


class TestClassifyConfidence(unittest.TestCase):
    def test_high(self):
        self.assertEqual(report.classify_confidence(85)["level"], "high")

    def test_medium(self):
        self.assertEqual(report.classify_confidence(60)["level"], "medium")

    def test_low(self):
        self.assertEqual(report.classify_confidence(30)["level"], "low")

    def test_insufficient(self):
        self.assertEqual(report.classify_confidence(10)["level"], "insufficient")


class TestGenerateReport(unittest.TestCase):
    def test_has_required_fields(self):
        result = report.generate_report()
        for key in ("confidence", "classification", "go_decision", "uncertainty_sources"):
            self.assertIn(key, result)

    def test_go_decision_bool(self):
        self.assertIsInstance(report.generate_report()["go_decision"]["proceed"], bool)

    def test_missing_inputs_do_not_earn_coverage_or_tracking_credit(self):
        result = report.generate_report()
        self.assertFalse(result["go_decision"]["proceed"])
        self.assertIsNone(result["data_inputs"]["fixture_coverage"])
        self.assertIsNone(result["data_inputs"]["api_tracked_pct"])
        self.assertEqual(result["confidence"]["confidence_score"], 0)

    def test_low_risk_findings_are_not_a_coverage_measurement(self):
        result = report.generate_report({"total_apis_detected": 10, "risk_distribution": {"low": 10}},
                                        {"risk_score": 0})
        self.assertIsNone(result["data_inputs"]["api_tracked_pct"])
        self.assertFalse(result["go_decision"]["proceed"])

    def test_optimistic_summary_alone_never_authorizes_rollout(self):
        result = report.generate_report(risk_report={"risk_score": 0}, fixture_coverage=1,
                                        api_tracked_pct=1,
                                        validation_result={"summary": {"total_tests": 100, "passed": 100, "verdict": "PASS"}})
        self.assertFalse(result["go_decision"]["proceed"])
        self.assertIsNone(result["data_inputs"]["validation_pass_rate"])


def measured_fixture(filesystem=False):
    """Synthetic validator-structure fixture, NOT evidence of runtime execution."""
    empty = hashlib.sha256(b"").hexdigest()
    stream = {"sha256": empty, "bytes_observed": 0, "retained_bytes": 0, "complete": True}
    leg = {"exit_code": 0, "termination": "exited", "streams": {"stdout": copy.deepcopy(stream),
                                                                         "stderr": copy.deepcopy(stream)}}
    if filesystem:
        leg["workspace_delta"] = {"sha256": "a" * 64, "changed_paths": 0}
    return {"schema_version": "migration-validation-v1", "phase": "execution", "comparison_mode": "exact-bytes",
            "validation_scope": "test-process-and-workspace-delta" if filesystem else "test-process-stdout-stderr-exit",
            "filesystem_comparison": filesystem, "inputs": {"baseline_sha256": "b" * 64, "migration_sha256": "c" * 64},
            "commands": {"baseline": ["/fixture/reference", "{test}"], "migration": ["/fixture/candidate", "{test}"]},
            "summary": {"total_tests": 1, "passed": 1, "failed": 0, "skipped": 0, "errored": 0, "verdict": "PASS"},
            "test_discovery": {"test_files_found": 1, "test_files": ["a.test.js"]}, "errors": [],
            "validation_results": [{"test": "a.test.js", "status": "PASS", "severity": "none", "band": "core",
                                    "divergences": [], "baseline": copy.deepcopy(leg), "migration": copy.deepcopy(leg)}]}


class TestValidationEvidence(unittest.TestCase):
    def assert_rejected(self, fixture):
        self.assertFalse(report.validation_evidence(fixture)["valid"])
        decision = report.generate_report(risk_report={"risk_score": 0}, validation_result=fixture,
                                          fixture_coverage=1, api_tracked_pct=1)
        self.assertFalse(decision["go_decision"]["proceed"])

    def test_consistent_observations_can_support_only_scoped_progression(self):
        for filesystem in (False, True):
            result = report.generate_report(risk_report={"risk_score": 0}, validation_result=measured_fixture(filesystem))
            self.assertTrue(result["validation_evidence"]["all_passed"])
            self.assertTrue(result["go_decision"]["proceed"])
            self.assertIn("not production authorization", result["go_decision"]["scope"])

    def test_summary_counts_must_reconcile_with_rows(self):
        for key, value in (("total_tests", 2), ("passed", True), ("failed", 1), ("skipped", 1), ("errored", 1)):
            with self.subTest(key=key):
                fixture = measured_fixture()
                fixture["summary"][key] = value
                self.assert_rejected(fixture)

    def test_missing_and_duplicate_case_rows_are_rejected(self):
        fixture = measured_fixture()
        fixture["validation_results"] = []
        self.assert_rejected(fixture)
        fixture = measured_fixture()
        fixture["validation_results"] *= 2
        fixture["summary"].update(total_tests=2, passed=2)
        fixture["test_discovery"] = {"test_files_found": 2, "test_files": ["a.test.js", "b.test.js"]}
        self.assert_rejected(fixture)

    def test_test_inventory_changes_are_rejected(self):
        for key in ("missing_baseline", "missing_migration"):
            fixture = measured_fixture()
            fixture["test_discovery"][key] = ["missing.test.js"]
            self.assert_rejected(fixture)

    def test_pass_cannot_mask_failed_or_truncated_execution(self):
        for key, value in (("exit_code", 1), ("exit_code", True), ("termination", "timeout"), ("termination", "signal")):
            fixture = measured_fixture()
            fixture["validation_results"][0]["migration"][key] = value
            self.assert_rejected(fixture)
        fixture = measured_fixture()
        fixture["validation_results"][0]["migration"]["streams"]["stdout"]["complete"] = False
        self.assert_rejected(fixture)

    def test_stream_digests_and_counts_cannot_disagree_with_pass(self):
        for channel in ("stdout", "stderr"):
            fixture = measured_fixture()
            stream = fixture["validation_results"][0]["migration"]["streams"][channel]
            stream.update(sha256=hashlib.sha256(b"x").hexdigest(), bytes_observed=1, retained_bytes=1)
            self.assert_rejected(fixture)

    def test_filesystem_mismatch_cannot_hide_behind_matching_stdout(self):
        fixture = measured_fixture(True)
        fixture["validation_results"][0]["migration"]["workspace_delta"]["sha256"] = "d" * 64
        self.assert_rejected(fixture)

    def test_real_failure_can_be_scored_but_never_authorizes_progression(self):
        fixture = measured_fixture()
        fixture["summary"].update(passed=0, failed=1, verdict="FAIL")
        row = fixture["validation_results"][0]
        row.update(status="FAIL", severity="critical", divergences=[{"channel": "migration", "reason": "exited", "exit_code": 1}])
        row["migration"]["exit_code"] = 1
        result = report.generate_report(risk_report={"risk_score": 0}, validation_result=fixture,
                                        fixture_coverage=1, api_tracked_pct=1)
        self.assertTrue(result["validation_evidence"]["valid"])
        self.assertEqual(result["data_inputs"]["validation_pass_rate"], 0)
        self.assertFalse(result["go_decision"]["proceed"])

    def test_static_critical_risk_overrides_passing_tests(self):
        result = report.generate_report({"risk_distribution": {"critical": 1}}, {"risk_score": 0}, measured_fixture())
        self.assertFalse(result["go_decision"]["proceed"])

    def test_malformed_or_design_only_results_are_rejected(self):
        for value in (None, {}, [], "PASS"):
            self.assert_rejected(value)
        fixture = measured_fixture()
        fixture["phase"] = "design"
        self.assert_rejected(fixture)

    def test_missing_input_and_command_bindings_are_rejected(self):
        for key in ("inputs", "commands"):
            fixture = measured_fixture()
            del fixture[key]
            self.assert_rejected(fixture)


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(report.self_test()["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
