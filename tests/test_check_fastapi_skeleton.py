"""Unit tests for scripts/check_fastapi_skeleton.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_fastapi_skeleton as mod


class TestConstants(unittest.TestCase):
    def test_endpoint_count(self):
        self.assertEqual(len(mod.ENDPOINTS), 12)

    def test_endpoint_paths_count(self):
        self.assertEqual(len(mod.ENDPOINT_PATHS), 12)

    def test_required_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 10)

    def test_required_methods_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 15)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 11)

    def test_required_integration_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_INTEGRATION_TESTS), 2)


class TestCheckFile(unittest.TestCase):
    def test_existing(self):
        result = mod.check_file(mod.IMPL, "implementation")
        self.assertTrue(result["pass"])

    def test_missing(self):
        result = mod.check_file(Path("/no"), "ghost")
        self.assertFalse(result["pass"])


class TestCheckContent(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, ["pub struct EndpointReport"], "type")
        self.assertTrue(results[0]["pass"])

    def test_missing(self):
        results = mod.check_content(mod.IMPL, ["NONEXISTENT_XYZ"], "type")
        self.assertFalse(results[0]["pass"])


class TestCheckImplTestCount(unittest.TestCase):
    def test_meets_minimum(self):
        result = mod.check_impl_test_count()
        self.assertTrue(result["pass"])


class TestRouteSources(unittest.TestCase):
    def test_route_sources_pass(self):
        results = mod.check_route_sources()
        for result in results:
            self.assertTrue(result["pass"], f"Failed: {result['check']}: {result['detail']}")


class TestCheckReport(unittest.TestCase):
    def test_report_passes(self):
        results = mod.check_report()
        for result in results:
            self.assertTrue(result["pass"], f"Failed: {result['check']}: {result['detail']}")

    def test_report_has_12_endpoints(self):
        results = mod.check_report()
        endpoint_check = [result for result in results if "12 base endpoints" in result["check"]]
        self.assertTrue(endpoint_check[0]["pass"])

    def test_report_all_endpoint_paths(self):
        results = mod.check_report()
        path_checks = [result for result in results if result["check"].startswith("Report: endpoint ")]
        self.assertEqual(len(path_checks), 12)
        for result in path_checks:
            self.assertTrue(result["pass"])


class TestCheckSpec(unittest.TestCase):
    def test_spec_passes(self):
        results = mod.check_spec()
        for result in results:
            self.assertTrue(result["pass"], f"Failed: {result['check']}")


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-2f5l")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.16")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, _ = mod.self_test()
        self.assertTrue(ok)


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-2f5l")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
            self.assertIn(key, result)


class TestAllTypes(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TYPES, "type")
        for result in results:
            self.assertTrue(result["pass"], result["check"])


class TestAllMethods(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_METHODS, "method")
        for result in results:
            self.assertTrue(result["pass"], result["check"])


class TestAllTests(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TESTS, "test")
        for result in results:
            self.assertTrue(result["pass"], result["check"])


class TestCargoVisibleIntegration(unittest.TestCase):
    def test_required_integration_tests_found(self):
        results = mod.check_content(
            mod.CARGO_INTEGRATION, mod.REQUIRED_INTEGRATION_TESTS, "integration test"
        )
        for result in results:
            self.assertTrue(result["pass"], result["check"])

    def test_required_integration_markers_found(self):
        results = mod.check_content(
            mod.CARGO_INTEGRATION, mod.INTEGRATION_MARKERS, "integration marker"
        )
        for result in results:
            self.assertTrue(result["pass"], result["check"])


class TestCompletionDebtEvidence(unittest.TestCase):
    def test_completion_debt_evidence_passes(self):
        results = mod.check_completion_debt_evidence()
        for result in results:
            self.assertTrue(result["pass"], f"Failed: {result['check']}: {result['detail']}")

    def test_completion_debt_evidence_missing_fails_closed(self):
        original = mod.REPLACEMENT_EVIDENCE
        try:
            mod.REPLACEMENT_EVIDENCE = Path("/no/completion-debt-evidence.json")
            results = mod.check_completion_debt_evidence()
        finally:
            mod.REPLACEMENT_EVIDENCE = original
        self.assertFalse(results[0]["pass"])
        self.assertIn("missing", results[0]["detail"])


if __name__ == "__main__":
    unittest.main()
