"""Unit tests for scripts/check_evidence_replay_validator.py"""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import textwrap
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

# Import the check script as a module
spec = importlib.util.spec_from_file_location(
    "check_evidence_replay_validator",
    ROOT / "scripts" / "check_evidence_replay_validator.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestCheckFileHelper(TestCase):
    def test_file_exists(self):
        result = mod.check_file(ROOT / "scripts" / "check_evidence_replay_validator.py", "self")
        self.assertTrue(result["pass"])
        self.assertIn("exists", result["detail"])

    def test_file_missing(self):
        result = mod.check_file(ROOT / "nonexistent_file.rs", "missing")
        self.assertFalse(result["pass"])
        self.assertIn("MISSING", result["detail"])


class TestCheckContentHelper(TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False)
        self.tmp.write("pub struct Foo;\npub enum Bar;\n")
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_pattern_found(self):
        results = mod.check_content(Path(self.tmp.name), ["pub struct Foo"], "type")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["pass"])

    def test_pattern_not_found(self):
        results = mod.check_content(Path(self.tmp.name), ["pub struct Baz"], "type")
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["pass"])

    def test_file_missing(self):
        results = mod.check_content(Path("/nonexistent.rs"), ["pub struct X"], "type")
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["pass"])
        self.assertIn("file missing", results[0]["detail"])


class TestCheckModuleRegistered(TestCase):
    def test_returns_two_checks(self):
        results = mod.check_module_registered()
        self.assertEqual(len(results), 2)

    def test_mod_rs_check_passes(self):
        results = mod.check_module_registered()
        mod_check = results[0]
        self.assertIn("tools/mod.rs", mod_check["check"])
        self.assertTrue(mod_check["pass"])

    def test_main_rs_check_passes(self):
        results = mod.check_module_registered()
        main_check = results[1]
        self.assertIn("main.rs", main_check["check"])
        self.assertTrue(main_check["pass"])


class TestCheckUpstream(TestCase):
    def test_ledger_exists(self):
        result = mod.check_upstream_ledger()
        self.assertTrue(result["pass"])

    def test_imports_ledger(self):
        result = mod.check_imports_ledger()
        self.assertTrue(result["pass"])


class TestCheckTestCount(TestCase):
    def test_real_impl_passes(self):
        result = mod.check_test_count(mod.IMPL)
        self.assertTrue(result["pass"])
        self.assertIn("minimum 30", result["detail"])

    def test_missing_file_fails(self):
        result = mod.check_test_count(Path("/nonexistent.rs"))
        self.assertFalse(result["pass"])


class TestRunChecks(TestCase):
    def test_full_run(self):
        result = mod.run_checks()
        self.assertIn("bead_id", result)
        self.assertEqual(result["bead_id"], "bd-2ona")
        self.assertEqual(result["section"], "10.14")
        self.assertIn("checks", result)
        self.assertIn("summary", result)
        self.assertIn("verdict", result)

    def test_verdict_is_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_pass(self):
        result = mod.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0, f"Failing checks: {failing}")

    def test_check_count_reasonable(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 70)

    def test_test_count_field(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["test_count"], 30)


class TestSelfTest(TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertIsInstance(checks, list)
        self.assertTrue(len(checks) > 0)


class TestRequiredConstants(TestCase):
    def test_required_types_nonempty(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 8)

    def test_required_methods_nonempty(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 10)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 3)

    def test_decision_kinds_count(self):
        self.assertEqual(len(mod.DECISION_KINDS), 7)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 30)


class TestJsonOutput(TestCase):
    def test_json_serializable(self):
        result = mod.run_checks()
        serialized = json.dumps(result)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["bead_id"], "bd-2ona")


if __name__ == "__main__":
    main()
