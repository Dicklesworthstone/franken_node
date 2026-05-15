"""Unit tests for scripts/check_category_shift.py."""
# ruff: noqa: E402

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_category_shift as mod


class TestConstants(unittest.TestCase):
    def test_required_structs_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_STRUCTS), 12)

    def test_required_enums_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_ENUMS), 6)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 4)

    def test_error_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_ERROR_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 4)

    def test_functions_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_FUNCTIONS), 9)

    def test_thresholds_count(self):
        self.assertEqual(len(mod.REQUIRED_THRESHOLDS), 3)

    def test_spec_sections_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_SPEC_SECTIONS), 9)

    def test_policy_sections_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_POLICY_SECTIONS), 8)


class TestFixtureReportAnalysis(unittest.TestCase):
    def test_five_dimensions(self):
        result = mod.analyze_fixture_report()
        self.assertEqual(result["dimensions_count"], 5)

    def test_claims_count(self):
        result = mod.analyze_fixture_report()
        self.assertEqual(result["claims_count"], 5)

    def test_all_claims_verified(self):
        result = mod.analyze_fixture_report()
        self.assertTrue(result["all_claims_verified"])

    def test_all_claim_dimensions_declared(self):
        result = mod.analyze_fixture_report()
        self.assertTrue(result["claim_dimensions_declared"])

    def test_thresholds_count(self):
        result = mod.analyze_fixture_report()
        self.assertEqual(result["thresholds_count"], 3)

    def test_all_thresholds_met(self):
        result = mod.analyze_fixture_report()
        self.assertTrue(result["all_thresholds_met"])

    def test_bet_status_count(self):
        result = mod.analyze_fixture_report()
        self.assertGreaterEqual(result["bet_status_count"], 3)

    def test_manifest_count(self):
        result = mod.analyze_fixture_report()
        self.assertGreaterEqual(result["manifest_count"], 5)

    def test_manifest_hashes_are_valid(self):
        result = mod.analyze_fixture_report()
        self.assertTrue(result["manifest_entries_have_hashes"])

    def test_report_hash_matches_payload(self):
        result = mod.analyze_fixture_report()
        self.assertTrue(result["report_hash_matches"])

    def test_json_format_supported(self):
        result = mod.analyze_fixture_report()
        self.assertTrue(result["has_json_format"])

    def test_markdown_format_supported(self):
        result = mod.analyze_fixture_report()
        self.assertTrue(result["has_markdown_format"])

    def test_missing_report_fails_closed(self):
        result = mod.analyze_fixture_report(report_path=ROOT / "no" / "report.json")
        self.assertFalse(result["valid_report"])
        self.assertFalse(result["has_json_format"])

    def test_invalid_report_fails_closed(self):
        with patch.object(
            mod, "_read_json_file", return_value=(None, "invalid JSON: broken")
        ):
            result = mod.analyze_fixture_report()
        self.assertFalse(result["valid_report"])
        self.assertIn("invalid JSON", result["detail"])


class TestRunAll(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_bead_id(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-15t")

    def test_section(self):
        result = mod.run_all()
        self.assertEqual(result["section"], "10.9")

    def test_zero_failing(self):
        result = mod.run_all()
        self.assertEqual(result["failed"], 0, self._failing(result))

    def test_many_checks(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 100)

    def test_report_fixture_checks_present(self):
        result = mod.run_all()
        check_names = {check["check"] for check in result["checks"]}
        self.assertIn("file: category shift reports checker", check_names)
        self.assertIn("fixture: category-shift directory", check_names)
        self.assertIn("fixture report: five dimensions", check_names)

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, checks = mod.self_test()
        failure_count = sum(1 for c in checks if not c["pass"])
        self.assertTrue(ok, f"self_test failed with {failure_count} failures")


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_all()
        parsed = json.JSONDecoder().decode(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-15t")

    def test_all_fields(self):
        result = mod.run_all()
        for key in [
            "bead_id",
            "title",
            "section",
            "verdict",
            "total",
            "passed",
            "failed",
            "checks",
        ]:
            self.assertIn(key, result)


class TestHelpers(unittest.TestCase):
    def test_sha256_hex_deterministic(self):
        h1 = mod._sha256_hex(b"test data")
        h2 = mod._sha256_hex(b"test data")
        self.assertEqual(h1, h2)

    def test_sha256_hex_different_inputs(self):
        h1 = mod._sha256_hex(b"data-a")
        h2 = mod._sha256_hex(b"data-b")
        self.assertNotEqual(h1, h2)

    def test_canonical_sort_keys(self):
        result = mod._canonical({"b": 1, "a": 2})
        keys = list(result.keys())
        self.assertEqual(keys, ["a", "b"])

    def test_expected_report_hash_matches_fixture(self):
        report, detail = mod._read_json_file(mod.FIXTURE_REPORT_JSON)
        self.assertEqual(detail, "valid JSON object")
        self.assertEqual(report["report_hash"], mod._expected_report_hash(report))

    def test_report_fixture_checks_pass(self):
        checks = mod.report_fixture_checks()
        failures = [check for check in checks if not check["pass"]]
        self.assertEqual(failures, [])


class TestFileChecks(unittest.TestCase):
    def test_impl_exists(self):
        result = mod.run_all()
        impl_check = next(
            c for c in result["checks"] if "category_shift implementation" in c["check"]
        )
        self.assertTrue(impl_check["pass"])

    def test_spec_exists(self):
        result = mod.run_all()
        spec_check = next(c for c in result["checks"] if "contract spec" in c["check"])
        self.assertTrue(spec_check["pass"])

    def test_policy_exists(self):
        result = mod.run_all()
        policy_check = next(c for c in result["checks"] if "reporting policy" in c["check"])
        self.assertTrue(policy_check["pass"])


if __name__ == "__main__":
    unittest.main()
