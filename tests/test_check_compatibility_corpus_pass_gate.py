"""Unit tests for scripts/check_compatibility_corpus_pass_gate.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_compatibility_corpus_pass_gate as mod


class TestConstants(unittest.TestCase):
    def test_bead_and_section(self):
        self.assertEqual(mod.BEAD_ID, "bd-28sz")
        self.assertEqual(mod.SECTION, "13")

    def test_required_event_codes(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 4)

    def test_required_families(self):
        self.assertEqual(len(mod.REQUIRED_FAMILIES), 16)

    def test_required_risk_bands(self):
        self.assertEqual(mod.REQUIRED_RISK_BANDS, {"critical", "high", "medium", "low"})


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


class TestHelpers(unittest.TestCase):
    def test_pass_rate(self):
        self.assertEqual(mod.pass_rate(95, 100), 95.0)
        self.assertEqual(mod.pass_rate(0, 0), 0.0)

    def test_aggregate_by_key(self):
        rows = [
            {"api_family": "fs", "status": "pass"},
            {"api_family": "fs", "status": "fail"},
            {"api_family": "http", "status": "pass"},
        ]
        agg = mod.aggregate_by_key(rows, "api_family")
        self.assertEqual(agg["fs"]["total"], 2)
        self.assertEqual(agg["fs"]["passed"], 1)
        self.assertEqual(agg["http"]["total"], 1)


class TestGateEvaluation(unittest.TestCase):
    def test_evaluate_gate_pass(self):
        data, _ = mod.load_report()
        eval_result = mod.evaluate_gate(data)
        self.assertTrue(eval_result["threshold_met"])
        self.assertFalse(eval_result["release_blocked"])
        self.assertFalse(eval_result["regression_detected"])

    def test_evaluate_gate_regression(self):
        data, _ = mod.load_report()
        data = json.loads(json.dumps(data))
        data["previous_release"]["overall_pass_rate_pct"] = 99.9
        eval_result = mod.evaluate_gate(data)
        self.assertTrue(eval_result["regression_detected"])
        self.assertTrue(eval_result["release_blocked"])


class TestReportChecks(unittest.TestCase):
    def test_report_checks_pass(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")

    def test_corpus_size_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        item = next(c for c in checks if c["check"] == "corpus: total test cases >= 500")
        self.assertTrue(item["pass"])

    def test_family_floor_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        item = next(c for c in checks if c["check"] == "gate: no family below 80%")
        self.assertTrue(item["pass"])

    def test_adversarial_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        item = next(c for c in checks if c["check"] == "adversarial: threshold drop blocks release")
        self.assertTrue(item["pass"])


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
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-28sz")


if __name__ == "__main__":
    unittest.main()
