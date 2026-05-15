"""Unit tests for scripts/check_temporal_concept_drift.py."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_temporal_concept_drift as mod  # noqa: E402


class TestConstants(unittest.TestCase):
    def test_bead_and_section(self):
        self.assertEqual(mod.BEAD_ID, "bd-v4ps")
        self.assertEqual(mod.SECTION, "12")

    def test_required_event_codes(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 5)

    def test_required_contract_terms(self):
        self.assertGreaterEqual(len(mod.REQUIRED_CONTRACT_TERMS), 9)


class TestFileChecks(unittest.TestCase):
    def test_contract_exists(self):
        result = mod.check_file(mod.CONTRACT, "contract")
        self.assertTrue(result["pass"])

    def test_report_exists(self):
        result = mod.check_file(mod.REPORT, "report")
        self.assertTrue(result["pass"])


class TestContractChecks(unittest.TestCase):
    def test_contract_passes(self):
        checks = mod.check_contract()
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")


class TestReportLoad(unittest.TestCase):
    def test_load_report_success(self):
        data, checks = mod.load_report()
        self.assertIsInstance(data, dict)
        self.assertTrue(all(c["pass"] for c in checks))

    def test_malformed_report_fails_closed(self):
        original_report = mod.REPORT
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                mod.REPORT = Path(tmpdir) / "temporal_concept_drift_report.json"
                mod.REPORT.write_text("{bad-json", encoding="utf-8")

                data, checks = mod.load_report()

            self.assertIsNone(data)
            self.assertFalse(checks[-1]["pass"])
            self.assertEqual(checks[-1]["check"], "report: valid json")
        finally:
            mod.REPORT = original_report

    def test_non_object_report_fails_closed(self):
        original_report = mod.REPORT
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                mod.REPORT = Path(tmpdir) / "temporal_concept_drift_report.json"
                mod.REPORT.write_text("[]", encoding="utf-8")

                data, checks = mod.load_report()

            self.assertIsNone(data)
            self.assertFalse(checks[-1]["pass"])
            self.assertEqual(checks[-1]["detail"], "not an object")
        finally:
            mod.REPORT = original_report


class TestEvidenceLoad(unittest.TestCase):
    def test_load_evidence_success(self):
        data, checks = mod.load_evidence()
        self.assertIsInstance(data, dict)
        self.assertTrue(all(c["pass"] for c in checks))

    def test_malformed_evidence_fails_closed(self):
        original_evidence = mod.EVIDENCE
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                mod.EVIDENCE = Path(tmpdir) / "verification_evidence.json"
                mod.EVIDENCE.write_text("{bad-json", encoding="utf-8")

                data, checks = mod.load_evidence()

            self.assertIsNone(data)
            self.assertFalse(checks[-1]["pass"])
            self.assertEqual(checks[-1]["check"], "evidence: valid json")
        finally:
            mod.EVIDENCE = original_evidence


class TestHelpers(unittest.TestCase):
    def test_evaluate_models_shape(self):
        data, _ = mod.load_report()
        out = mod.evaluate_models(data)
        for key in [
            "models_total",
            "models_stale",
            "stale_models_blocked",
            "models_exceeding_drift_threshold",
            "recalibration_run_ids_valid",
            "drift_threshold_pct",
        ]:
            self.assertIn(key, out)

    def test_evaluate_models_values(self):
        data, _ = mod.load_report()
        out = mod.evaluate_models(data)
        self.assertEqual(out["models_total"], 3)
        self.assertGreaterEqual(out["models_stale"], 1)


class TestReportChecks(unittest.TestCase):
    def test_report_checks_pass(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")

    def test_scenario_b_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        item = next(c for c in checks if c["check"] == "scenario B: >5% drift triggers recalibration")
        self.assertTrue(item["pass"])

    def test_adversarial_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        item = next(c for c in checks if c["check"] == "adversarial: stale-model unblock attempt is detected")
        self.assertTrue(item["pass"])

    def test_pipeline_fixture_boundary_requires_execution_mode(self):
        data, _ = mod.load_report()
        evidence, _ = mod.load_evidence()
        tampered = copy.deepcopy(data)
        tampered["recalibration_pipeline"].pop("execution_mode")

        checks = mod.check_report(tampered, evidence)

        item = next(c for c in checks if c["check"] == "pipeline: fixture execution mode is explicit")
        self.assertFalse(item["pass"])

    def test_pipeline_fixture_boundary_rejects_live_claim(self):
        data, _ = mod.load_report()
        evidence, _ = mod.load_evidence()
        tampered = copy.deepcopy(data)
        tampered["recalibration_pipeline"]["live_recalibration_claimed"] = True

        checks = mod.check_report(tampered, evidence)

        item = next(
            c for c in checks
            if c["check"] == "pipeline: synthetic fixture is not claimed as live recalibration"
        )
        self.assertFalse(item["pass"])

    def test_pipeline_command_evidence_required(self):
        data, _ = mod.load_report()
        evidence, _ = mod.load_evidence()
        tampered_evidence = copy.deepcopy(evidence)
        tampered_evidence["commands"] = []

        checks = mod.check_report(data, tampered_evidence)

        item = next(
            c for c in checks
            if c["check"] == "pipeline: verification commands are recorded as passing"
        )
        self.assertFalse(item["pass"])

    def test_pipeline_source_evidence_required(self):
        data, _ = mod.load_report()
        evidence, _ = mod.load_evidence()
        tampered = copy.deepcopy(data)
        tampered["recalibration_pipeline"]["evidence"]["source_paths"] = []

        checks = mod.check_report(tampered, evidence)

        item = next(c for c in checks if c["check"] == "pipeline: fixture evidence source paths exist")
        self.assertFalse(item["pass"])


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")

    def test_summary_counts(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)
        self.assertGreater(result["summary"]["passing"], 0)

    def test_result_shape(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
            self.assertIn(key, result)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 0)


class TestJsonRoundTrip(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_checks()
        blob = json.dumps(result, indent=2)
        parsed = json.JSONDecoder().decode(blob)
        self.assertEqual(parsed["bead_id"], "bd-v4ps")


if __name__ == "__main__":
    unittest.main()
