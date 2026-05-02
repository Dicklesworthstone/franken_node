"""Unit tests for scripts/check_frankensqlite_adapter.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_frankensqlite_adapter as mod


class TestConstants(unittest.TestCase):
    def test_persistence_domains_count(self):
        self.assertEqual(len(mod.PERSISTENCE_DOMAINS), 24)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 6)

    def test_event_codes_prefixed(self):
        for code in mod.EVENT_CODES:
            self.assertTrue(code.startswith("FRANKENSQLITE_"))

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_invariants_prefixed(self):
        for inv in mod.INVARIANTS:
            self.assertTrue(inv.startswith("INV-FSA-"))

    def test_required_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 9)

    def test_required_methods_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 15)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 40)


class TestCheckFile(unittest.TestCase):
    def test_existing_file(self):
        result = mod.check_file(mod.IMPL, "conformance test")
        self.assertTrue(result["pass"])

    def test_missing_file(self):
        result = mod.check_file(Path("/nonexistent"), "ghost")
        self.assertFalse(result["pass"])


class TestCheckContent(unittest.TestCase):
    def test_found_patterns(self):
        results = mod.check_content(mod.IMPL, ["pub enum SafetyTier"], "type")
        self.assertTrue(results[0]["pass"])

    def test_missing_patterns(self):
        results = mod.check_content(mod.IMPL, ["NONEXISTENT_XYZ"], "type")
        self.assertFalse(results[0]["pass"])


class TestCheckImplTestCount(unittest.TestCase):
    def test_meets_minimum(self):
        result = mod.check_impl_test_count()
        self.assertTrue(result["pass"])
        count = int(result["detail"].split()[0])
        self.assertGreaterEqual(count, 40)


class TestCheckSerdeDerives(unittest.TestCase):
    def test_serde_present(self):
        result = mod.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckReport(unittest.TestCase):
    def test_report_passes(self):
        results = mod.check_report()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_report_verdict(self):
        results = mod.check_report()
        verdict_checks = [r for r in results if "gate verdict" in r["check"]]
        self.assertTrue(verdict_checks[0]["pass"])

    def test_report_results_match_matrix_count(self):
        results = mod.check_report()
        count_checks = [
            r
            for r in results
            if f"{len(mod.PERSISTENCE_DOMAINS)} conformance" in r["check"]
        ]
        self.assertTrue(count_checks[0]["pass"])

    def test_report_tier_counts(self):
        results = mod.check_report()
        tier_checks = [r for r in results if "tier" in r["check"] and "count" in r["check"]]
        self.assertEqual(len(tier_checks), 3)
        for r in tier_checks:
            self.assertTrue(r["pass"], r["detail"])


class TestCheckSpec(unittest.TestCase):
    def test_spec_passes(self):
        results = mod.check_spec()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")


class TestCheckPersistenceDomains(unittest.TestCase):
    def test_all_domains_found(self):
        results = mod.check_persistence_domains()
        for r in results:
            self.assertTrue(r["pass"], f"Missing domain: {r['check']}")

    def test_domain_count(self):
        results = mod.check_persistence_domains()
        self.assertEqual(len(results), 24)


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-2tua")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.16")

    def test_summary_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)

    def test_checks_have_required_keys(self):
        result = mod.run_checks()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self):
        ok, checks = mod.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_checks()
        output = json.dumps(result, indent=2)
        parsed = json.loads(output)
        self.assertEqual(parsed["bead_id"], "bd-2tua")

    def test_json_has_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict",
                     "test_count", "summary", "checks"]:
            self.assertIn(key, result)


class TestContentCheckAllTypes(unittest.TestCase):
    def test_all_types_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TYPES, "type")
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")


class TestContentCheckAllMethods(unittest.TestCase):
    def test_all_methods_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_METHODS, "method")
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")


class TestContentCheckAllEvents(unittest.TestCase):
    def test_all_events_found(self):
        results = mod.check_content(mod.IMPL, mod.EVENT_CODES, "event_code")
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")


class TestContentCheckAllInvariants(unittest.TestCase):
    def test_all_invariants_found(self):
        results = mod.check_content(mod.IMPL, mod.INVARIANTS, "invariant")
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")


class TestContentCheckAllTests(unittest.TestCase):
    def test_all_tests_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TESTS, "test")
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")


if __name__ == "__main__":
    unittest.main()
