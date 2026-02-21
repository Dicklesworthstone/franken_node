"""Unit tests for scripts/check_hardening_perf_regression.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_hardening_perf_regression as mod


class TestConstants(unittest.TestCase):
    def test_bead_and_section(self):
        self.assertEqual(mod.BEAD_ID, "bd-2w4u")
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


class TestMetrics(unittest.TestCase):
    def test_p99_overhead_balanced(self):
        data, _ = mod.load_report()
        value = mod.p99_overhead_pct(data, "balanced")
        self.assertLessEqual(value, 15.0)

    def test_throughput_retention_balanced(self):
        data, _ = mod.load_report()
        value = mod.throughput_retention_pct(data, "balanced")
        self.assertGreaterEqual(value, 85.0)

    def test_benchmark_blocking_logic(self):
        data, _ = mod.load_report()
        ok, _ = mod.check_benchmark_blocking(data["ci_benchmark_runs"])
        self.assertTrue(ok)

    def test_benchmark_blocking_negative(self):
        runs = [{"pr": "#x", "regression_pct": 6.0, "blocked_merge": False}]
        ok, detail = mod.check_benchmark_blocking(runs)
        self.assertFalse(ok)
        self.assertIn("not blocked", detail)


class TestScenarioChecks(unittest.TestCase):
    def test_scenario_a(self):
        data, _ = mod.load_report()
        scenario = mod.scenario_by_id(data, "A")
        self.assertIsNotNone(scenario)
        self.assertTrue(scenario["documented"])

    def test_scenario_b(self):
        data, _ = mod.load_report()
        scenario = mod.scenario_by_id(data, "B")
        self.assertIsNotNone(scenario)
        self.assertTrue(scenario["p99_within_15pct"])
        self.assertTrue(scenario["throughput_at_least_85pct"])

    def test_scenario_c(self):
        data, _ = mod.load_report()
        scenario = mod.scenario_by_id(data, "C")
        self.assertIsNotNone(scenario)
        self.assertGreaterEqual(scenario["injected_latency_regression_pct"], 20.0)
        self.assertTrue(scenario["ci_blocked_merge"])

    def test_scenario_d(self):
        data, _ = mod.load_report()
        scenario = mod.scenario_by_id(data, "D")
        self.assertIsNotNone(scenario)
        self.assertTrue(scenario["switch_without_restart"])
        self.assertEqual(scenario["request_failures"], 0)


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
        self.assertEqual(parsed["bead_id"], "bd-2w4u")


if __name__ == "__main__":
    unittest.main()
