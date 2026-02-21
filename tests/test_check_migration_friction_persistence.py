"""Unit tests for scripts/check_migration_friction_persistence.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_migration_friction_persistence as mod


class TestConstants(unittest.TestCase):
    def test_bead_and_section(self):
        self.assertEqual(mod.BEAD_ID, "bd-3jc1")
        self.assertEqual(mod.SECTION, "12")

    def test_required_event_codes(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 5)

    def test_required_contract_terms(self):
        self.assertGreaterEqual(len(mod.REQUIRED_CONTRACT_TERMS), 7)


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


class TestMetrics(unittest.TestCase):
    def test_coverage_calculation(self):
        data, _ = mod.load_report()
        coverage = mod.autopilot_coverage_pct(data["projects"])
        self.assertGreaterEqual(coverage, 80.0)

    def test_high_confidence_success_rate(self):
        data, _ = mod.load_report()
        rate = mod.high_confidence_success_rate(data["projects"], 80)
        self.assertGreaterEqual(rate, 90.0)


class TestReportChecks(unittest.TestCase):
    def test_report_checks_pass(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")

    def test_scenario_a_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        items = [c for c in checks if c["check"] == "scenario A: express starter"]
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["pass"])

    def test_scenario_b_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        items = [c for c in checks if c["check"] == "scenario B: native addon blocker"]
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["pass"])

    def test_scenario_c_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        items = [c for c in checks if c["check"] == "scenario C: mixed-mode partial migration"]
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["pass"])


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
        self.assertEqual(parsed["bead_id"], "bd-3jc1")


if __name__ == "__main__":
    unittest.main()
