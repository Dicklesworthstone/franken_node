#!/usr/bin/env python3
"""Unit tests for scripts/check_conformance_suite.py (bd-3i6c).

Tests both the module-level API and the CLI interface of the conformance
suite verification gate.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_conformance_suite as mod


class TestConstants(unittest.TestCase):
    """Verify the verification script's own constants are consistent."""

    def test_domain_prefixes_count(self):
        self.assertEqual(len(mod.DOMAIN_PREFIXES), 4)

    def test_domain_minimums_count(self):
        self.assertEqual(len(mod.DOMAIN_MINIMUMS), 4)

    def test_domain_minimums_values(self):
        self.assertEqual(mod.DOMAIN_MINIMUMS["determinism"], 10)
        self.assertEqual(mod.DOMAIN_MINIMUMS["idempotency"], 8)
        self.assertEqual(mod.DOMAIN_MINIMUMS["epoch_validity"], 12)
        self.assertEqual(mod.DOMAIN_MINIMUMS["proof_correctness"], 10)

    def test_fixture_files_count(self):
        self.assertEqual(len(mod.FIXTURE_FILES), 4)

    def test_lib_types_count(self):
        self.assertGreaterEqual(len(mod.LIB_TYPES), 8)

    def test_lib_ops_count(self):
        self.assertGreaterEqual(len(mod.LIB_OPS), 8)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 6)

    def test_error_codes_count(self):
        self.assertEqual(len(mod.ERROR_CODES), 8)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 6)

    def test_rust_test_domains_count(self):
        self.assertEqual(len(mod.RUST_TEST_DOMAINS), 4)


class TestConformanceIdRegex(unittest.TestCase):
    """Verify the conformance ID regex matches expected patterns."""

    def test_valid_det(self):
        self.assertRegex("FSQL-DET-001", mod.CONFORMANCE_ID_RE)

    def test_valid_idp(self):
        self.assertRegex("FSQL-IDP-099", mod.CONFORMANCE_ID_RE)

    def test_valid_epo(self):
        self.assertRegex("FSQL-EPO-012", mod.CONFORMANCE_ID_RE)

    def test_valid_prf(self):
        self.assertRegex("FSQL-PRF-010", mod.CONFORMANCE_ID_RE)

    def test_invalid_prefix(self):
        self.assertNotRegex("FSQL-XYZ-001", mod.CONFORMANCE_ID_RE)

    def test_invalid_number(self):
        self.assertNotRegex("FSQL-DET-01", mod.CONFORMANCE_ID_RE)

    def test_invalid_format(self):
        self.assertNotRegex("DET-001", mod.CONFORMANCE_ID_RE)


class TestCheckFiles(unittest.TestCase):
    """Verify file existence checks work correctly."""

    def test_all_files_exist(self):
        results = mod.check_lib_files()
        for r in results:
            self.assertTrue(r["pass"], f"File missing: {r['check']}")

    def test_file_count(self):
        results = mod.check_lib_files()
        self.assertEqual(len(results), 2)  # spec + library module


class TestCheckFixtureFiles(unittest.TestCase):
    """Verify fixture file checks."""

    def test_all_fixture_files_exist(self):
        results = mod.check_fixture_files()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")

    def test_fixture_file_count(self):
        results = mod.check_fixture_files()
        self.assertEqual(len(results), 4)


class TestLoadFixtures(unittest.TestCase):
    """Verify fixture loading works correctly."""

    def test_load_returns_fixtures_and_no_errors(self):
        fixtures, errors = mod.load_fixtures()
        self.assertEqual(len(errors), 0, f"Load errors: {errors}")
        self.assertGreaterEqual(len(fixtures), 40)

    def test_all_fixtures_have_conformance_id(self):
        fixtures, _ = mod.load_fixtures()
        for f in fixtures:
            self.assertIn("conformance_id", f, "Missing conformance_id in fixture")

    def test_all_fixtures_have_domain(self):
        fixtures, _ = mod.load_fixtures()
        for f in fixtures:
            self.assertIn("domain", f, "Missing domain in fixture")


class TestFixtureCount(unittest.TestCase):
    """Verify fixture count checks."""

    def test_total_fixture_count(self):
        fixtures, _ = mod.load_fixtures()
        results = mod.check_fixture_count(fixtures)
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_domain_minimums(self):
        fixtures, _ = mod.load_fixtures()
        results = mod.check_domain_minimums(fixtures)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")


class TestConformanceIdChecks(unittest.TestCase):
    """Verify conformance ID format and uniqueness checks."""

    def test_id_format(self):
        fixtures, _ = mod.load_fixtures()
        results = mod.check_conformance_id_format(fixtures)
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_no_duplicates(self):
        fixtures, _ = mod.load_fixtures()
        results = mod.check_no_duplicate_ids(fixtures)
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_prefix_alignment(self):
        fixtures, _ = mod.load_fixtures()
        results = mod.check_domain_prefix_alignment(fixtures)
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestFixtureSchema(unittest.TestCase):
    """Verify fixture schema checks."""

    def test_all_fields_present(self):
        fixtures, _ = mod.load_fixtures()
        results = mod.check_fixture_schema(fixtures)
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestLibraryModuleChecks(unittest.TestCase):
    """Verify library module checks pass."""

    def test_module_wired(self):
        results = mod.check_lib_module_wired()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_lib_types(self):
        results = mod.check_lib_types()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")

    def test_lib_domains(self):
        results = mod.check_lib_domains()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")

    def test_lib_prefixes(self):
        results = mod.check_lib_prefixes()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")

    def test_lib_ops(self):
        results = mod.check_lib_ops()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")

    def test_lib_event_codes(self):
        results = mod.check_lib_event_codes()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_lib_error_codes(self):
        results = mod.check_lib_error_codes()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_lib_invariants(self):
        results = mod.check_lib_invariants()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_lib_schema_version(self):
        results = mod.check_lib_schema_version()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_lib_suite_version(self):
        results = mod.check_lib_suite_version()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_lib_serde(self):
        results = mod.check_lib_serde()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_lib_test_count(self):
        results = mod.check_lib_test_count()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestRustSuiteChecks(unittest.TestCase):
    """Verify Rust test suite checks pass."""

    def test_suite_file_exists(self):
        results = mod.check_rust_suite_file()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_suite_tests(self):
        results = mod.check_rust_suite_tests()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_suite_conformance_ids(self):
        results = mod.check_rust_suite_conformance_ids()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestSpecSections(unittest.TestCase):
    """Verify spec contract sections are present."""

    def test_spec_sections(self):
        results = mod.check_spec_sections()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")


class TestRunChecks(unittest.TestCase):
    """Verify the aggregate run_checks function."""

    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"],
                        f"Failed checks: {[c for c in result['checks'] if not c['pass']]}")

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-3i6c")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.14")

    def test_verdict(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_summary_counts(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)
        self.assertEqual(result["summary"]["passing"], result["summary"]["total"])


class TestSelfTest(unittest.TestCase):
    """Verify the self_test function."""

    def test_self_test_passes(self):
        ok, msg = mod.self_test()
        self.assertTrue(ok, msg)

    def test_self_test_message(self):
        ok, msg = mod.self_test()
        self.assertEqual(msg, "self_test passed")


class TestCliInterface(unittest.TestCase):
    """Verify the CLI interface works correctly."""

    def test_exit_code_zero(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_conformance_suite.py")],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_human_output_contains_pass(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_conformance_suite.py")],
            capture_output=True, text=True
        )
        self.assertIn("PASS", result.stdout)

    def test_json_flag_produces_valid_json(self):
        out = subprocess.check_output(
            [sys.executable, str(ROOT / "scripts" / "check_conformance_suite.py"), "--json"],
            text=True
        )
        data = json.loads(out)
        self.assertIn("bead_id", data)
        self.assertEqual(data["bead_id"], "bd-3i6c")
        self.assertTrue(data["overall_pass"])

    def test_json_has_checks_array(self):
        out = subprocess.check_output(
            [sys.executable, str(ROOT / "scripts" / "check_conformance_suite.py"), "--json"],
            text=True
        )
        data = json.loads(out)
        self.assertIsInstance(data["checks"], list)
        self.assertGreater(len(data["checks"]), 0)

    def test_self_test_cli(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_conformance_suite.py"), "--self-test"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("self_test passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
