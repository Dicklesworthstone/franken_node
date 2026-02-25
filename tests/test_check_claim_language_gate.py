"""Unit tests for scripts/check_claim_language_gate.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_claim_language_gate as mod


class TestConstants(unittest.TestCase):
    """Verify module-level constants are well-formed."""

    def test_claim_categories_count(self):
        self.assertEqual(len(mod.CLAIM_CATEGORIES), 4)

    def test_claim_categories_content(self):
        for cat in ["Tui", "Api", "Storage", "Model"]:
            self.assertIn(cat, mod.CLAIM_CATEGORIES)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 6)

    def test_event_codes_prefixed(self):
        for code in mod.EVENT_CODES:
            self.assertTrue(code.startswith("CLAIM_"))

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_invariants_prefixed(self):
        for inv in mod.INVARIANTS:
            self.assertTrue(inv.startswith("INV-CLG-"))

    def test_required_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 6)

    def test_required_methods_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 10)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 30)


class TestCheckFile(unittest.TestCase):
    """Tests for check_file()."""

    def test_existing_file(self):
        result = mod.check_file(mod.IMPL, "conformance test")
        self.assertTrue(result["pass"])
        self.assertIn("exists", result["detail"])

    def test_missing_file(self):
        result = mod.check_file(Path("/nonexistent/file.rs"), "ghost")
        self.assertFalse(result["pass"])
        self.assertIn("MISSING", result["detail"])


class TestCheckContent(unittest.TestCase):
    """Tests for check_content()."""

    def test_found_patterns(self):
        results = mod.check_content(mod.IMPL, ["pub enum ClaimCategory"], "type")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["pass"])

    def test_missing_patterns(self):
        results = mod.check_content(mod.IMPL, ["NONEXISTENT_SYMBOL_XYZ"], "type")
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = mod.check_content(Path("/no/file"), ["anything"], "cat")
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["pass"])
        self.assertEqual(results[0]["detail"], "file missing")


class TestCheckImplTestCount(unittest.TestCase):
    """Tests for check_impl_test_count()."""

    def test_meets_minimum(self):
        result = mod.check_impl_test_count()
        self.assertTrue(result["pass"])
        self.assertIn("tests", result["detail"])

    def test_count_at_least_30(self):
        result = mod.check_impl_test_count()
        count = int(result["detail"].split()[0])
        self.assertGreaterEqual(count, 30)


class TestCheckSerdeDerives(unittest.TestCase):
    """Tests for check_serde_derives()."""

    def test_serde_present(self):
        result = mod.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckReport(unittest.TestCase):
    """Tests for check_report()."""

    def test_report_checks_pass(self):
        results = mod.check_report()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_report_has_verdict(self):
        results = mod.check_report()
        verdict_checks = [r for r in results if "gate verdict" in r["check"]]
        self.assertEqual(len(verdict_checks), 1)
        self.assertTrue(verdict_checks[0]["pass"])

    def test_report_has_claims(self):
        results = mod.check_report()
        claim_checks = [r for r in results if "claims present" in r["check"]]
        self.assertEqual(len(claim_checks), 1)
        self.assertTrue(claim_checks[0]["pass"])

    def test_report_all_categories(self):
        results = mod.check_report()
        cat_checks = [r for r in results if "all categories" in r["check"]]
        self.assertEqual(len(cat_checks), 1)
        self.assertTrue(cat_checks[0]["pass"])

    def test_report_zero_unlinked(self):
        results = mod.check_report()
        unlinked_checks = [r for r in results if "zero unlinked" in r["check"]]
        self.assertEqual(len(unlinked_checks), 1)
        self.assertTrue(unlinked_checks[0]["pass"])

    def test_report_zero_broken(self):
        results = mod.check_report()
        broken_checks = [r for r in results if "zero broken" in r["check"]]
        self.assertEqual(len(broken_checks), 1)
        self.assertTrue(broken_checks[0]["pass"])


class TestCheckPolicyDoc(unittest.TestCase):
    """Tests for check_policy_doc()."""

    def test_policy_doc_passes(self):
        results = mod.check_policy_doc()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_policy_doc_categories(self):
        results = mod.check_policy_doc()
        cat_results = [r for r in results if "category" in r["check"]]
        self.assertEqual(len(cat_results), 4)

    def test_policy_doc_sections(self):
        results = mod.check_policy_doc()
        section_results = [r for r in results if "section" in r["check"]]
        self.assertEqual(len(section_results), 3)


class TestRunChecks(unittest.TestCase):
    """Tests for run_checks() integration."""

    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-2ji2")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.16")

    def test_summary_counts(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)
        self.assertGreaterEqual(result["summary"]["passing"], 80)
        self.assertEqual(
            result["summary"]["total"],
            result["summary"]["passing"] + result["summary"]["failing"],
        )

    def test_checks_list_not_empty(self):
        result = mod.run_checks()
        self.assertGreater(len(result["checks"]), 0)

    def test_each_check_has_required_keys(self):
        result = mod.run_checks()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)


class TestSelfTest(unittest.TestCase):
    """Tests for self_test()."""

    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self):
        ok, checks = mod.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


class TestJsonOutput(unittest.TestCase):
    """Tests for --json output format."""

    def test_json_serializable(self):
        result = mod.run_checks()
        output = json.dumps(result, indent=2)
        parsed = json.loads(output)
        self.assertEqual(parsed["bead_id"], "bd-2ji2")

    def test_json_has_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict",
                     "test_count", "summary", "checks"]:
            self.assertIn(key, result)


class TestContentCheckTypes(unittest.TestCase):
    """Verify all required types are found in impl."""

    def test_all_types_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TYPES, "type")
        for r in results:
            self.assertTrue(r["pass"], f"Missing type: {r['check']}")


class TestContentCheckMethods(unittest.TestCase):
    """Verify all required methods are found in impl."""

    def test_all_methods_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_METHODS, "method")
        for r in results:
            self.assertTrue(r["pass"], f"Missing method: {r['check']}")


class TestContentCheckEvents(unittest.TestCase):
    """Verify all event codes are found in impl."""

    def test_all_events_found(self):
        results = mod.check_content(mod.IMPL, mod.EVENT_CODES, "event_code")
        for r in results:
            self.assertTrue(r["pass"], f"Missing event: {r['check']}")


class TestContentCheckInvariants(unittest.TestCase):
    """Verify all invariants are found in impl."""

    def test_all_invariants_found(self):
        results = mod.check_content(mod.IMPL, mod.INVARIANTS, "invariant")
        for r in results:
            self.assertTrue(r["pass"], f"Missing invariant: {r['check']}")


class TestContentCheckTests(unittest.TestCase):
    """Verify all required test names are found in impl."""

    def test_all_tests_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TESTS, "test")
        for r in results:
            self.assertTrue(r["pass"], f"Missing test: {r['check']}")


if __name__ == "__main__":
    unittest.main()
