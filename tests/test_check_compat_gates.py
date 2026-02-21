"""Unit tests for scripts/check_compat_gates.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_compat_gates as mod


class TestConstants(unittest.TestCase):
    def test_required_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 14)

    def test_required_methods_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 14)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 8)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_compatibility_bands_count(self):
        self.assertEqual(len(mod.COMPATIBILITY_BANDS), 4)

    def test_compatibility_modes_count(self):
        self.assertEqual(len(mod.COMPATIBILITY_MODES), 3)

    def test_divergence_actions_count(self):
        self.assertEqual(len(mod.DIVERGENCE_ACTIONS), 4)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 34)

    def test_legacy_types_count(self):
        self.assertGreaterEqual(len(mod.LEGACY_TYPES), 10)

    def test_legacy_methods_count(self):
        self.assertGreaterEqual(len(mod.LEGACY_METHODS), 10)


class TestCheckFile(unittest.TestCase):
    def test_existing(self):
        result = mod.check_file(mod.IMPL, "test")
        self.assertTrue(result["pass"])

    def test_missing(self):
        result = mod.check_file(Path("/nonexistent/file.rs"), "ghost")
        self.assertFalse(result["pass"])


class TestCheckContent(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, ["pub enum CompatibilityBand"], "type")
        self.assertTrue(results[0]["pass"])

    def test_missing(self):
        results = mod.check_content(mod.IMPL, ["NONEXISTENT_PATTERN_XYZ"], "type")
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = mod.check_content(Path("/no"), ["anything"], "type")
        self.assertFalse(results[0]["pass"])


class TestCheckImplTestCount(unittest.TestCase):
    def test_meets_minimum(self):
        result = mod.check_impl_test_count()
        self.assertTrue(result["pass"])


class TestCheckLegacyTestCount(unittest.TestCase):
    def test_meets_minimum(self):
        result = mod.check_legacy_test_count()
        self.assertTrue(result["pass"])


class TestCheckSpec(unittest.TestCase):
    def test_spec_passes(self):
        results = mod.check_spec()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")


class TestCheckModuleRegistered(unittest.TestCase):
    def test_registered(self):
        result = mod.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckBandModeMatrix(unittest.TestCase):
    def test_complete(self):
        result = mod.check_band_mode_matrix_complete()
        self.assertTrue(result["pass"])


class TestCheckSerdeDerives(unittest.TestCase):
    def test_sufficient(self):
        result = mod.check_serde_derives()
        self.assertTrue(result["pass"])


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"], self._failing_details(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-137")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.5")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0, self._failing_details(result))

    def test_has_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 50)

    def _failing_details(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, msg = mod.self_test()
        self.assertTrue(ok, msg)


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-137")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
            self.assertIn(key, result)


class TestAllTypes(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TYPES, "type")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllMethods(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_METHODS, "method")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllEvents(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.EVENT_CODES, "event_code")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllInvariants(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.INVARIANTS, "invariant")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllTests(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TESTS, "test")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestLegacyTypes(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.LEGACY_IMPL, mod.LEGACY_TYPES, "legacy_type")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestLegacyMethods(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.LEGACY_IMPL, mod.LEGACY_METHODS, "legacy_method")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


if __name__ == "__main__":
    unittest.main()
