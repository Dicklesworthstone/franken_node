"""Tests for scripts/check_repro_bundle_export.py (bd-2808)."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_repro_bundle_export",
    ROOT / "scripts" / "check_repro_bundle_export.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestCheckFileHelper(TestCase):
    def test_file_exists(self):
        result = mod.check_file(mod.IMPL, "self")
        self.assertTrue(result["pass"])

    def test_file_missing(self):
        result = mod.check_file(ROOT / "nonexistent.rs", "missing")
        self.assertFalse(result["pass"])


class TestCheckContentHelper(TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False)
        self.tmp.write("pub struct Foo;\npub enum Bar;\n")
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_found(self):
        results = mod.check_content(Path(self.tmp.name), ["pub struct Foo"], "type")
        self.assertTrue(results[0]["pass"])

    def test_not_found(self):
        results = mod.check_content(Path(self.tmp.name), ["pub struct Baz"], "type")
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = mod.check_content(Path("/nonexistent.rs"), ["x"], "type")
        self.assertFalse(results[0]["pass"])


class TestCheckModuleRegistered(TestCase):
    def test_registered(self):
        result = mod.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckTestCount(TestCase):
    def test_real_impl(self):
        result = mod.check_test_count()
        self.assertTrue(result["pass"])


class TestCheckSchemaVersion(TestCase):
    def test_schema_version(self):
        result = mod.check_schema_version()
        self.assertTrue(result["pass"])


class TestCheckDefaultHasher(TestCase):
    def test_hasher(self):
        result = mod.check_default_hasher()
        self.assertTrue(result["pass"])


class TestRunChecks(TestCase):
    def test_full_run(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-2808")
        self.assertEqual(result["section"], "10.14")

    def test_verdict_is_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_pass(self):
        result = mod.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0, f"Failing: {failing}")

    def test_check_count_reasonable(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 80)

    def test_test_count_field(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["test_count"], 25)


class TestSelfTest(TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)


class TestRequiredConstants(TestCase):
    def test_types_count(self):
        self.assertEqual(len(mod.REQUIRED_TYPES), 11)

    def test_methods_count(self):
        self.assertEqual(len(mod.REQUIRED_METHODS), 14)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 3)

    def test_required_tests_count(self):
        self.assertEqual(len(mod.REQUIRED_TESTS), 39)

    def test_trace_event_types_count(self):
        self.assertEqual(len(mod.TRACE_EVENT_TYPES), 6)

    def test_failure_types_count(self):
        self.assertEqual(len(mod.FAILURE_TYPES), 4)


class TestJsonOutput(TestCase):
    def test_json_serializable(self):
        result = mod.run_checks()
        serialized = json.dumps(result)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["bead_id"], "bd-2808")

    def test_cli_json(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_repro_bundle_export.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["verdict"], "PASS")


class TestSummaryIntegrity(TestCase):
    def test_no_failing_checks(self):
        result = mod.run_checks()
        s = result["summary"]
        self.assertEqual(s["failing"], 0)
        self.assertEqual(s["passing"], s["total"])


if __name__ == "__main__":
    main()
