"""Unit tests for scripts/check_category_shift.py."""
# ruff: noqa: E402

import json
import sys
import unittest
from pathlib import Path

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


class TestSimulatePipeline(unittest.TestCase):
    def test_five_dimensions(self):
        result = mod.simulate_pipeline()
        self.assertEqual(result["dimensions_count"], 5)

    def test_claims_count(self):
        result = mod.simulate_pipeline()
        self.assertEqual(result["claims_count"], 5)

    def test_all_claims_verified(self):
        result = mod.simulate_pipeline()
        self.assertTrue(result["all_claims_verified"])

    def test_all_claims_have_reproduce_scripts(self):
        result = mod.simulate_pipeline()
        self.assertTrue(result["all_claims_have_scripts"])

    def test_thresholds_count(self):
        result = mod.simulate_pipeline()
        self.assertEqual(result["thresholds_count"], 3)

    def test_all_thresholds_met(self):
        result = mod.simulate_pipeline()
        self.assertTrue(result["all_thresholds_met"])

    def test_bet_status_count(self):
        result = mod.simulate_pipeline()
        self.assertGreaterEqual(result["bet_status_count"], 3)

    def test_manifest_count(self):
        result = mod.simulate_pipeline()
        self.assertGreaterEqual(result["manifest_count"], 5)

    def test_idempotency(self):
        result = mod.simulate_pipeline()
        self.assertTrue(result["idempotent"])

    def test_json_format_supported(self):
        result = mod.simulate_pipeline()
        self.assertTrue(result["has_json_format"])

    def test_markdown_format_supported(self):
        result = mod.simulate_pipeline()
        self.assertTrue(result["has_markdown_format"])


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
        self.assertTrue(ok, f"self_test failed with {sum(1 for c in checks if not c['pass'])} failures")


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_all()
        parsed = json.JSONDecoder().decode(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-15t")

    def test_all_fields(self):
        result = mod.run_all()
        for key in ["bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"]:
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

    def test_build_claim_structure(self):
        claim = mod._build_claim(
            "CSR-TEST-001", "test_dim", "test summary",
            99.0, "percent", "artifacts/test.json", '{"key":"value"}',
            10_000_000 - 1000, 10_000_000, 30 * 24 * 3600,
        )
        self.assertEqual(claim["claim_id"], "CSR-TEST-001")
        self.assertEqual(claim["dimension"], "test_dim")
        self.assertEqual(claim["outcome"], "verified")
        self.assertIn("sha256sum", claim["reproduce_script"])

    def test_build_claim_stale(self):
        claim = mod._build_claim(
            "CSR-TEST-002", "test_dim", "stale claim",
            50.0, "percent", "artifacts/stale.json", '{"old":true}',
            10_000_000 - (31 * 24 * 3600), 10_000_000, 30 * 24 * 3600,
        )
        self.assertEqual(claim["outcome"], "stale")
        self.assertEqual(claim["evidence"]["freshness"], "stale")

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
