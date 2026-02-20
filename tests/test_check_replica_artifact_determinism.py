"""Unit tests for scripts/check_replica_artifact_determinism.py"""

import importlib.util
import json
import os
import tempfile
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

# Import the check script as a module
spec = importlib.util.spec_from_file_location(
    "check_replica_artifact_determinism",
    ROOT / "scripts" / "check_replica_artifact_determinism.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestCheckFileHelper(TestCase):
    def test_file_exists(self):
        result = mod.check_file(mod.IMPL, "conformance test")
        self.assertTrue(result["pass"])
        self.assertIn("exists", result["detail"])

    def test_file_missing(self):
        result = mod.check_file(ROOT / "nonexistent_file.rs", "missing")
        self.assertFalse(result["pass"])
        self.assertIn("MISSING", result["detail"])


class TestCheckContentHelper(TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False)
        self.tmp.write("struct Foo;\nstruct Bar;\n")
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_pattern_found(self):
        results = mod.check_content(Path(self.tmp.name), ["struct Foo"], "type")
        self.assertTrue(results[0]["pass"])

    def test_pattern_not_found(self):
        results = mod.check_content(Path(self.tmp.name), ["struct Baz"], "type")
        self.assertFalse(results[0]["pass"])

    def test_file_missing(self):
        results = mod.check_content(Path("/nonexistent.rs"), ["x"], "type")
        self.assertFalse(results[0]["pass"])


class TestCheckFixtures(TestCase):
    def test_all_fixtures_found(self):
        results = mod.check_fixtures()
        # 3 files × 2 checks each (existence + golden vectors)
        self.assertEqual(len(results), 6)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_fixture_golden_vectors(self):
        results = mod.check_fixtures()
        golden_checks = [r for r in results if "golden" in r["check"]]
        self.assertEqual(len(golden_checks), 3)
        for r in golden_checks:
            self.assertTrue(r["pass"])


class TestCheckUpstream(TestCase):
    def test_upstream_exists(self):
        results = mod.check_upstream()
        self.assertGreaterEqual(len(results), 3)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")


class TestCheckImports(TestCase):
    def test_imports_present(self):
        result = mod.check_imports()
        self.assertTrue(result["pass"])


class TestCheckTestCount(TestCase):
    def test_real_impl_passes(self):
        result = mod.check_test_count(mod.IMPL)
        self.assertTrue(result["pass"])
        self.assertIn("minimum 15", result["detail"])

    def test_missing_file_fails(self):
        result = mod.check_test_count(Path("/nonexistent.rs"))
        self.assertFalse(result["pass"])


class TestCheckReplicaCount(TestCase):
    def test_configurable_replicas(self):
        result = mod.check_replica_count()
        self.assertTrue(result["pass"])


class TestRunChecks(TestCase):
    def test_full_run(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-1iyx")
        self.assertEqual(result["section"], "10.14")
        self.assertIn("checks", result)
        self.assertIn("verdict", result)

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

    def test_fixture_count_field(self):
        result = mod.run_checks()
        self.assertEqual(result["fixture_count"], 3)


class TestSelfTest(TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertIsInstance(checks, list)


class TestRequiredConstants(TestCase):
    def test_required_types_count(self):
        self.assertEqual(len(mod.REQUIRED_TYPES), 3)

    def test_required_functions_count(self):
        self.assertEqual(len(mod.REQUIRED_FUNCTIONS), 5)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 3)

    def test_required_tests_count(self):
        self.assertEqual(len(mod.REQUIRED_TESTS), 19)

    def test_fixture_files_count(self):
        self.assertEqual(len(mod.FIXTURE_FILES), 3)

    def test_divergence_fields_count(self):
        self.assertEqual(len(mod.DIVERGENCE_FIELDS), 7)

    def test_domain_tags_count(self):
        self.assertEqual(len(mod.DOMAIN_TAGS), 5)


class TestJsonOutput(TestCase):
    def test_json_serializable(self):
        result = mod.run_checks()
        serialized = json.dumps(result)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["bead_id"], "bd-1iyx")


if __name__ == "__main__":
    main()
