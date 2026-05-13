"""Unit tests for scripts/check_release_vectors.py (bd-1hd)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_release_vectors as checker  # noqa: E402


class TestSelfTest(unittest.TestCase):
    def test_self_test_runs(self):
        ok = checker.self_test()
        self.assertTrue(ok)

    def test_self_test_reflects_failed_verdict(self):
        failing_result = {
            "checks": [{"name": "forced_failure", "passed": False, "detail": "forced"}],
            "verdict": "FAIL",
            "all_passed": False,
        }
        with patch.object(checker, "run_all", return_value=failing_result):
            self.assertFalse(checker.self_test())

    def test_cli_self_test_exits_on_failed_verdict(self):
        failing_result = {
            "checks": [{"name": "forced_failure", "passed": False, "detail": "forced"}],
            "verdict": "FAIL",
            "all_passed": False,
        }
        with (
            patch.object(checker, "run_all", return_value=failing_result),
            patch.object(sys, "argv", ["check_release_vectors.py", "--self-test"]),
            patch("builtins.print"),
        ):
            with self.assertRaises(SystemExit) as ctx:
                checker.main()
        self.assertEqual(ctx.exception.code, 1)


class TestManifestLoading(unittest.TestCase):
    def test_load_manifest_missing_returns_sentinel(self):
        with patch.object(checker, "_read", return_value=""):
            self.assertIsNone(checker._load_manifest())

    def test_load_manifest_invalid_returns_sentinel(self):
        with patch.object(checker, "_read", return_value="{"):
            self.assertIsNone(checker._load_manifest())


class TestRunAllStructure(unittest.TestCase):
    def test_structure(self):
        result = checker.run_all()
        for key in ("bead_id", "section", "checks", "verdict",
                     "passed", "failed", "total", "all_passed", "status"):
            self.assertIn(key, result)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-1hd")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.10")

    def test_title(self):
        result = checker.run_all()
        self.assertEqual(result["title"], "Release Gate Vector Suites")

    def test_all_checks_have_required_keys(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_pass_values_are_bool(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIsInstance(check["passed"], bool)

    def test_verdict_consistency(self):
        result = checker.run_all()
        if result["failed"] == 0:
            self.assertEqual(result["verdict"], "PASS")
            self.assertTrue(result["all_passed"])


class TestSpecChecks(unittest.TestCase):
    def test_spec_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "spec_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_event_codes(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_event:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_invariants(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_invariant:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_error_codes(self):
        result = checker.run_all()
        for code in checker.ERROR_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_error:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")


class TestManifestChecks(unittest.TestCase):
    def test_manifest_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "manifest_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_manifest_valid_json(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "manifest_valid_json")
        self.assertTrue(check["passed"], check["detail"])

    def test_manifest_has_suites(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "manifest_has_suites")
        self.assertTrue(check["passed"], check["detail"])

    def test_manifest_suite_fields(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "manifest_suite_fields")
        self.assertTrue(check["passed"], check["detail"])

    def test_manifest_version(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "manifest_version")
        self.assertTrue(check["passed"], check["detail"])


class TestVectorSuiteChecks(unittest.TestCase):
    def test_vector_files_exist(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "vector_files_exist")
        self.assertTrue(check["passed"], check["detail"])

    def test_vector_files_valid_json(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "vector_files_valid_json")
        self.assertTrue(check["passed"], check["detail"])


class TestCoverageChecks(unittest.TestCase):
    def test_coverage_report_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "coverage_report_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_coverage_report_valid(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "coverage_report_valid")
        self.assertTrue(check["passed"], check["detail"])


class TestConstants(unittest.TestCase):
    def test_event_code_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 7)

    def test_invariant_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_error_code_count(self):
        self.assertEqual(len(checker.ERROR_CODES), 5)

    def test_manifest_field_count(self):
        self.assertEqual(len(checker.REQUIRED_MANIFEST_FIELDS), 7)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_all()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_release_vectors.py"), "--json"],
            capture_output=True, check=True, text=True, timeout=10,
        )
        decoder = json.JSONDecoder()
        try:
            data = decoder.decode(proc.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"invalid JSON output: {exc}\nstdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertEqual(data["bead_id"], "bd-1hd")
        self.assertIn("checks", data)

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_release_vectors.py"), "--self-test"],
            capture_output=True, check=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("self_test passed", proc.stdout)


class TestOverallVerdict(unittest.TestCase):
    def test_all_pass(self):
        result = checker.run_all()
        failing = [c["name"] for c in result["checks"] if not c["passed"]]
        self.assertEqual(result["verdict"], "PASS",
                         f"Failed checks: {failing}")


if __name__ == "__main__":
    unittest.main()
