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

    def test_evidence_ref_helper_exists(self):
        result = mod.check_file(mod.EVIDENCE_REF_HELPER, "helper")
        self.assertTrue(result["pass"])

    def test_schema_file_exists(self):
        result = mod.check_file(mod.SCHEMA, "schema")
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
    def test_event_bound(self):
        result = mod.check_event_bound()
        self.assertTrue(result["pass"])


class TestPathTruth(TestCase):
    def test_real_path_truth_passes(self):
        results = mod.check_path_truth()
        for result in results:
            self.assertTrue(result["pass"], f"Failed: {result['check']}: {result['detail']}")


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
        self.assertGreaterEqual(result["summary"]["total"], 50)

    def test_test_count_field(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["test_count"], 15)


class TestSelfTest(TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)


class TestRequiredConstants(TestCase):
    def test_types_count(self):
        self.assertEqual(len(mod.REQUIRED_TYPES), 8)

    def test_methods_count(self):
        self.assertEqual(len(mod.REQUIRED_METHODS), 7)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 3)

    def test_required_tests_count(self):
        self.assertEqual(len(mod.REQUIRED_TESTS), 15)

    def test_bundle_fields_count(self):
        self.assertEqual(len(mod.REQUIRED_BUNDLE_FIELDS), 6)

    def test_helper_patterns_count(self):
        self.assertEqual(len(mod.HELPER_PATTERNS), 4)


class TestJsonOutput(TestCase):
    def test_json_serializable(self):
        result = mod.run_checks()
        serialized = json.dumps(result)
        parsed = json.JSONDecoder().decode(serialized)
        self.assertEqual(parsed["bead_id"], "bd-2808")

    def test_cli_json(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_repro_bundle_export.py"), "--json"],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        data = json.JSONDecoder().decode(result.stdout)
        self.assertEqual(data["verdict"], "PASS")


class TestSummaryIntegrity(TestCase):
    def test_no_failing_checks(self):
        result = mod.run_checks()
        s = result["summary"]
        self.assertEqual(s["failing"], 0)
        self.assertEqual(s["passing"], s["total"])


class TestCommentOnlyRegression(TestCase):
    def test_comment_only_source_markers_fail_closed(self):
        commented_impl = "\n".join(
            [
                *(f"// {marker}" for marker in mod.REQUIRED_TYPES),
                *(f"// {marker}" for marker in mod.REQUIRED_METHODS),
                *(f"// {marker}" for marker in mod.EVENT_CODES),
                *(f"// {marker}" for marker in mod.INVARIANTS),
                *(f"// {marker}" for marker in mod.REQUIRED_TESTS),
                *(f"// {marker}" for marker in mod.REQUIRED_BUNDLE_FIELDS),
                "// SCHEMA_VERSION schema_version",
                "// MAX_EVENTS EVT_REPRO_EXPORTED",
                "/*",
                *("// #[test]\n// fn commented_test() {}" for _ in range(15)),
                "*/",
            ]
        )
        commented_helper = "\n".join(f"// {marker}" for marker in mod.HELPER_PATTERNS)

        original_impl = mod.IMPL
        original_helper = mod.EVIDENCE_REF_HELPER
        original_mod = mod.MOD_RS
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            impl_path = tmp / "lab_runtime.rs"
            helper_path = tmp / "repro_bundle_export.rs"
            mod_path = tmp / "mod.rs"
            impl_path.write_text(commented_impl, encoding="utf-8")
            helper_path.write_text(commented_helper, encoding="utf-8")
            mod_path.write_text("// pub mod repro_bundle_export;\n", encoding="utf-8")

            try:
                mod.IMPL = impl_path
                mod.EVIDENCE_REF_HELPER = helper_path
                mod.MOD_RS = mod_path
                result = mod.run_checks()
            finally:
                mod.IMPL = original_impl
                mod.EVIDENCE_REF_HELPER = original_helper
                mod.MOD_RS = original_mod

        checks = {check["check"]: check["pass"] for check in result["checks"]}
        self.assertTrue(checks["file: lab runtime implementation"])
        self.assertTrue(checks["file: EvidenceRef portability helper"])
        self.assertTrue(checks["file: schema artifact"])
        self.assertTrue(checks["schema_field: schema_version"])
        self.assertEqual(result["test_count"], 0)

        expected_failures = [
            "EvidenceRef helper registered in tools/mod.rs",
            "lab runtime unit test count",
            "schema version constant",
            "bounded repro events",
        ]
        expected_failures.extend(f"type: {marker}" for marker in mod.REQUIRED_TYPES)
        expected_failures.extend(f"method: {marker}" for marker in mod.REQUIRED_METHODS)
        expected_failures.extend(f"event_code: {marker}" for marker in mod.EVENT_CODES)
        expected_failures.extend(f"invariant: {marker}" for marker in mod.INVARIANTS)
        expected_failures.extend(f"test: {marker}" for marker in mod.REQUIRED_TESTS)
        expected_failures.extend(f"bundle_field: {marker}" for marker in mod.REQUIRED_BUNDLE_FIELDS)
        expected_failures.extend(
            f"evidence_ref_helper: {marker}" for marker in mod.HELPER_PATTERNS
        )
        for check_name in expected_failures:
            self.assertIn(check_name, checks)
            self.assertFalse(checks[check_name], check_name)


if __name__ == "__main__":
    main()
