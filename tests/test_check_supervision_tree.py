"""Unit tests for scripts/check_supervision_tree.py (bd-3he)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_supervision_tree as mod


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


class TestChecksStructure(unittest.TestCase):
    def setUp(self):
        self.results = mod._checks()

    def test_minimum_check_count(self):
        self.assertGreaterEqual(len(self.results), 41)

    def test_checks_have_required_fields(self):
        for r in self.results:
            self.assertIn("check", r)
            self.assertIn("passed", r)
            self.assertIn("detail", r)

    def test_check_names_unique(self):
        names = [r["check"] for r in self.results]
        self.assertEqual(len(names), len(set(names)))


class TestSourceExists(unittest.TestCase):
    def test_source_found(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["SOURCE_EXISTS"]["passed"])


class TestModuleWired(unittest.TestCase):
    def test_module_wired(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["MODULE_WIRED"]["passed"])


class TestCoreTypes(unittest.TestCase):
    def test_all_types_present(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["CORE_TYPES"]["passed"])
        self.assertIn("3/3", results["CORE_TYPES"]["detail"])


class TestStrategyVariants(unittest.TestCase):
    def test_all_strategy_variants(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["STRATEGY_VARIANTS"]["passed"])
        self.assertIn("3/3", results["STRATEGY_VARIANTS"]["detail"])


class TestRestartTypeVariants(unittest.TestCase):
    def test_all_restart_type_variants(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["RESTART_TYPE_VARIANTS"]["passed"])
        self.assertIn("3/3", results["RESTART_TYPE_VARIANTS"]["detail"])


class TestKeyMethods(unittest.TestCase):
    def test_all_methods_present(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["KEY_METHODS"]["passed"])
        self.assertIn("4/4", results["KEY_METHODS"]["detail"])


class TestEventCodes(unittest.TestCase):
    def test_all_event_codes(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["EVENT_CODES"]["passed"])
        self.assertIn("8/8", results["EVENT_CODES"]["detail"])


class TestErrorCodes(unittest.TestCase):
    def test_all_error_codes(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["ERROR_CODES"]["passed"])
        self.assertIn("5/5", results["ERROR_CODES"]["detail"])


class TestInvariants(unittest.TestCase):
    def test_all_invariants(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["INVARIANTS"]["passed"])
        self.assertIn("5/5", results["INVARIANTS"]["detail"])


class TestSchemaVersion(unittest.TestCase):
    def test_schema_version(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["SCHEMA_VERSION"]["passed"])


class TestUnitTests(unittest.TestCase):
    def test_sufficient_tests(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["UNIT_TESTS"]["passed"])


class TestJsonOutput(unittest.TestCase):
    def test_json_output_parseable(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_supervision_tree.py"), "--json"],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        self.assertEqual(data["bead"], "bd-3he")
        self.assertEqual(data["title"], "Supervision Tree with Restart Budgets and Escalation Policies")
        self.assertIn("verdict", data)
        self.assertIn("passed", data)
        self.assertIn("total", data)
        self.assertIn("checks", data)

    def test_verdict_is_pass(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_supervision_tree.py"), "--json"],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["passed"], data["total"])

    def test_exit_code_zero_on_pass(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_supervision_tree.py"), "--json"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0)


class TestHumanOutput(unittest.TestCase):
    def test_human_output_contains_bead(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_supervision_tree.py")],
            capture_output=True, text=True
        )
        self.assertIn("bd-3he", result.stdout)
        self.assertIn("PASS", result.stdout)


class TestSelfTestCli(unittest.TestCase):
    def test_self_test_exit_code(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_supervision_tree.py"), "--self-test"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0)


class TestOverallVerdict(unittest.TestCase):
    def test_all_checks_pass(self):
        results = mod._checks()
        failed = [r for r in results if not r["passed"]]
        self.assertEqual(len(failed), 0,
                         f"Failing checks: {[r['check'] for r in failed]}")


class TestBd18spCompletionDebt(unittest.TestCase):
    def setUp(self):
        self.results = {r["check"]: r for r in mod._checks()}

    def test_replacement_evidence_is_checked(self):
        self.assertTrue(self.results["BD18SP_REPLACEMENT_EVIDENCE_EXISTS"]["passed"])
        self.assertTrue(self.results["BD18SP_REPLACEMENT_EVIDENCE_JSON"]["passed"])
        self.assertTrue(self.results["BD18SP_REPLACEMENT_BEAD_ID"]["passed"])
        self.assertTrue(self.results["BD18SP_COMPLETION_DEBT_BEAD_ID"]["passed"])

    def test_all_completion_debt_items_are_covered(self):
        self.assertTrue(self.results["BD18SP_COMPLETION_DEBT_ITEMS_COVERED"]["passed"])
        for spec_item in mod.COMPLETION_DEBT_ITEMS:
            self.assertTrue(self.results[f"BD18SP_{spec_item}_EVIDENCE_PATHS"]["passed"])
            self.assertTrue(self.results[f"BD18SP_{spec_item}_TEST_NAMES"]["passed"])

    def test_property_and_integration_markers_are_checked(self):
        for marker in mod.PROPERTY_TEST_MARKERS:
            self.assertTrue(self.results[f"BD18SP_PROPERTY_MARKER_{marker}"]["passed"])
        for marker in mod.INTEGRATION_TEST_MARKERS:
            self.assertTrue(self.results[f"BD18SP_INTEGRATION_MARKER_{marker}"]["passed"])

    def test_e2e_hyperfine_artifacts_are_checked(self):
        self.assertTrue(self.results["BD18SP_E2E_HYPERFINE_SCRIPT"]["passed"])
        self.assertTrue(self.results["BD18SP_E2E_HYPERFINE_RESULTS"]["passed"])


if __name__ == "__main__":
    unittest.main()
