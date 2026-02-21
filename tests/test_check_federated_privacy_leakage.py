"""Unit tests for scripts/check_federated_privacy_leakage.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_federated_privacy_leakage as mod


class TestConstants(unittest.TestCase):
    def test_bead_and_section(self):
        self.assertEqual(mod.BEAD_ID, "bd-1nab")
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


class TestBudgetLogic(unittest.TestCase):
    def test_default_budget_check(self):
        data, _ = mod.load_report()
        self.assertTrue(mod.channel_default_budget_ok(data["channels"]))

    def test_exhaustion_blocking_check(self):
        data, _ = mod.load_report()
        self.assertTrue(mod.channel_exhaustion_blocking_ok(data["channels"]))

    def test_exhaustion_blocking_negative(self):
        channels = [
            {
                "channel": "x",
                "epsilon_budget": 0.5,
                "epsilon_consumed": 0.5,
                "emissions_allowed": 5,
                "emissions_attempted": 6,
                "n_plus_one_blocked": False,
                "blocked_error": "ERR_PRIVACY_BUDGET_EXHAUSTED",
            }
        ]
        self.assertFalse(mod.channel_exhaustion_blocking_ok(channels))


class TestScenarioChecks(unittest.TestCase):
    def test_scenario_a(self):
        data, _ = mod.load_report()
        scenario = mod.find_scenario(data, "A")
        self.assertIsNotNone(scenario)
        self.assertTrue(scenario["exhaustion_blocked"])

    def test_scenario_b(self):
        data, _ = mod.load_report()
        scenario = mod.find_scenario(data, "B")
        self.assertIsNotNone(scenario)
        self.assertGreaterEqual(scenario["participants"], 10)
        self.assertFalse(scenario["recovery_succeeded"])

    def test_scenario_c(self):
        data, _ = mod.load_report()
        scenario = mod.find_scenario(data, "C")
        self.assertIsNotNone(scenario)
        self.assertTrue(scenario["verifier_reports_exhausted"])

    def test_scenario_d(self):
        data, _ = mod.load_report()
        scenario = mod.find_scenario(data, "D")
        self.assertIsNotNone(scenario)
        self.assertTrue(scenario["reset_denied"])
        self.assertEqual(scenario["logged_event"], "FPL-005")


class TestReportChecks(unittest.TestCase):
    def test_report_checks_pass(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")


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
        self.assertEqual(parsed["bead_id"], "bd-1nab")


if __name__ == "__main__":
    unittest.main()
