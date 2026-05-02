"""Unit tests for scripts/check_frankentui_migration.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_frankentui_migration as mod


class TestConstants(unittest.TestCase):
    """Verify module-level constants are well-formed."""

    def test_contract_modules_count(self):
        self.assertEqual(len(mod.CONTRACT_MODULES), 7)

    def test_frankentui_components_count(self):
        self.assertEqual(len(mod.FRANKENTUI_COMPONENTS), 7)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 3)

    def test_event_codes_prefixed(self):
        for code in mod.EVENT_CODES:
            self.assertTrue(code.startswith("FRANKENTUI_"))

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_invariants_prefixed(self):
        for inv in mod.INVARIANTS:
            self.assertTrue(inv.startswith("INV-FTM-"))

    def test_required_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 7)

    def test_required_methods_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 10)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 35)


class TestCheckFile(unittest.TestCase):
    def test_existing_file(self):
        result = mod.check_file(mod.IMPL, "integration test")
        self.assertTrue(result["pass"])

    def test_missing_file(self):
        result = mod.check_file(Path("/nonexistent/file.rs"), "ghost")
        self.assertFalse(result["pass"])
        self.assertIn("MISSING", result["detail"])


class TestCheckContent(unittest.TestCase):
    def test_found_patterns(self):
        results = mod.check_content(mod.IMPL, ["pub enum FrankentuiComponent"], "type")
        self.assertTrue(results[0]["pass"])

    def test_missing_patterns(self):
        results = mod.check_content(mod.IMPL, ["NONEXISTENT_XYZ"], "type")
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = mod.check_content(Path("/no/file"), ["anything"], "cat")
        self.assertFalse(results[0]["pass"])


class TestCheckImplTestCount(unittest.TestCase):
    def test_meets_minimum(self):
        result = mod.check_impl_test_count()
        self.assertTrue(result["pass"])
        count = int(result["detail"].split()[0])
        self.assertGreaterEqual(count, 35)


class TestCheckSerdeDerives(unittest.TestCase):
    def test_serde_present(self):
        result = mod.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckInventoryCsv(unittest.TestCase):
    def test_csv_passes(self):
        results = mod.check_inventory_csv()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_csv_row_count(self):
        results = mod.check_inventory_csv()
        row_checks = [r for r in results if "row count" in r["check"]]
        self.assertEqual(len(row_checks), 1)
        self.assertTrue(row_checks[0]["pass"])

    def test_csv_all_complete(self):
        results = mod.check_inventory_csv()
        complete_checks = [r for r in results if "all complete" in r["check"]]
        self.assertEqual(len(complete_checks), 1)
        self.assertTrue(complete_checks[0]["pass"])

    def test_csv_module_coverage(self):
        results = mod.check_inventory_csv()
        module_checks = [r for r in results if r["check"].startswith("inventory CSV: module")]
        self.assertEqual(len(module_checks), 7)
        for r in module_checks:
            self.assertTrue(r["pass"], f"Missing module: {r['check']}")

    def test_csv_component_coverage(self):
        results = mod.check_inventory_csv()
        comp_checks = [r for r in results if r["check"].startswith("inventory CSV: component")]
        self.assertEqual(len(comp_checks), 7)
        for r in comp_checks:
            self.assertTrue(r["pass"], f"Missing component: {r['check']}")

    def test_csv_required_columns(self):
        results = mod.check_inventory_csv()
        col_checks = [r for r in results if r["check"].startswith("inventory CSV: column")]
        self.assertGreaterEqual(len(col_checks), 5)
        for r in col_checks:
            self.assertTrue(r["pass"], f"Missing column: {r['check']}")


class TestCheckSpec(unittest.TestCase):
    def test_spec_passes(self):
        results = mod.check_spec()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_spec_has_required_sections(self):
        results = mod.check_spec()
        section_checks = [r for r in results if "section" in r["check"]]
        self.assertGreaterEqual(len(section_checks), 5)


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-1xtf")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.16")

    def test_summary_counts(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)
        self.assertGreaterEqual(result["summary"]["passing"], 90)

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
        parsed = json.JSONDecoder().decode(output)
        self.assertEqual(parsed["bead_id"], "bd-1xtf")

    def test_json_has_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict",
                     "test_count", "summary", "checks"]:
            self.assertIn(key, result)


class TestContentCheckAllTypes(unittest.TestCase):
    def test_all_types_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TYPES, "type")
        for r in results:
            self.assertTrue(r["pass"], f"Missing type: {r['check']}")


class TestContentCheckAllMethods(unittest.TestCase):
    def test_all_methods_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_METHODS, "method")
        for r in results:
            self.assertTrue(r["pass"], f"Missing method: {r['check']}")


class TestContentCheckAllEvents(unittest.TestCase):
    def test_all_events_found(self):
        results = mod.check_content(mod.IMPL, mod.EVENT_CODES, "event_code")
        for r in results:
            self.assertTrue(r["pass"], f"Missing event: {r['check']}")


class TestContentCheckAllInvariants(unittest.TestCase):
    def test_all_invariants_found(self):
        results = mod.check_content(mod.IMPL, mod.INVARIANTS, "invariant")
        for r in results:
            self.assertTrue(r["pass"], f"Missing invariant: {r['check']}")


class TestContentCheckAllTests(unittest.TestCase):
    def test_all_tests_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TESTS, "test")
        for r in results:
            self.assertTrue(r["pass"], f"Missing test: {r['check']}")


if __name__ == "__main__":
    unittest.main()
