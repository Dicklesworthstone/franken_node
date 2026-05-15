#!/usr/bin/env python3
"""Unit tests for check_control_evidence.py verification script."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_control_evidence as checker  # noqa: E402


class TestCheckFileHelper(unittest.TestCase):
    def test_file_exists(self):
        result = checker.check_file(checker.IMPL, "implementation")
        self.assertTrue(result["pass"])

    def test_file_missing(self):
        result = checker.check_file(Path("/nonexistent/file.rs"), "missing")
        self.assertFalse(result["pass"])

    def test_detail_on_exists(self):
        result = checker.check_file(checker.IMPL, "implementation")
        self.assertIn("exists:", result["detail"])

    def test_detail_on_missing(self):
        result = checker.check_file(Path("/nonexistent"), "x")
        self.assertIn("MISSING", result["detail"])


class TestCheckContentHelper(unittest.TestCase):
    def test_found(self):
        results = checker.check_content(checker.IMPL, ["pub enum DecisionType"], "type")
        self.assertTrue(results[0]["pass"])

    def test_not_found(self):
        results = checker.check_content(checker.IMPL, ["NONEXISTENT_XYZ"], "type")
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = checker.check_content(Path("/nonexistent"), ["pattern"], "cat")
        self.assertFalse(results[0]["pass"])

    def test_multiple(self):
        results = checker.check_content(
            checker.IMPL,
            ["pub enum DecisionType", "pub enum DecisionKind"],
            "type",
        )
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["pass"] for r in results))


class TestCheckModuleRegistered(unittest.TestCase):
    def test_registered(self):
        result = checker.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckTestCount(unittest.TestCase):
    def test_minimum_40(self):
        result = checker.check_test_count()
        self.assertTrue(result["pass"])
        count = int(result["detail"].split()[0])
        self.assertGreaterEqual(count, 40)


class TestCheckSerdeDerive(unittest.TestCase):
    def test_serde(self):
        result = checker.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckSamplesJsonl(unittest.TestCase):
    def test_samples_exist(self):
        results = checker.check_samples_jsonl()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_has_enough_entries(self):
        results = checker.check_samples_jsonl()
        count_check = [r for r in results if "entry count" in r["check"]]
        self.assertTrue(len(count_check) > 0)
        self.assertTrue(count_check[0]["pass"])

    def test_all_decision_types(self):
        results = checker.check_samples_jsonl()
        types_check = [r for r in results if "decision types" in r["check"]]
        self.assertTrue(len(types_check) > 0)
        self.assertTrue(types_check[0]["pass"])


class TestConformanceTest(unittest.TestCase):
    def test_conformance_test_exists(self):
        result = checker.check_file(checker.CONFORMANCE_TEST, "policy evidence required conformance test")
        self.assertTrue(result["pass"])

    def test_policy_evidence_required_sentinel_present(self):
        results = checker.check_content(
            checker.CONFORMANCE_TEST,
            [checker.POLICY_EVIDENCE_REQUIRED_SENTINEL],
            "conformance_test",
        )
        self.assertTrue(results[0]["pass"])


class TestCheckSpecContent(unittest.TestCase):
    def test_spec_has_all_types(self):
        results = checker.check_spec_content()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")


class TestRunChecks(unittest.TestCase):
    def test_full_run(self):
        result = checker.run_checks()
        self.assertIn("checks", result)
        self.assertIn("summary", result)

    def test_all_checks_pass(self):
        result = checker.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            f"Failing checks: {json.dumps(failing, indent=2)}",
        )

    def test_verdict_is_pass(self):
        result = checker.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_title_field(self):
        result = checker.run_checks()
        self.assertIn("evidence", result["title"].lower())

    def test_test_count_field(self):
        result = checker.run_checks()
        count = int(result["test_count"])
        self.assertGreaterEqual(count, 40)

    def test_check_count_reasonable(self):
        result = checker.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 85)

    def test_comment_only_source_markers_fail_closed(self):
        commented_tests = "\n".join(
            f"// #[test]\n// fn {test_name}() {{}}" for test_name in checker.REQUIRED_TESTS
        )
        comment_only_impl = "\n".join(
            [
                *(f"// {marker}" for marker in checker.REQUIRED_TYPES),
                *(f"// {marker}" for marker in checker.REQUIRED_METHODS),
                *(f"// {code}" for code in checker.EVENT_CODES),
                *(f"// {invariant}" for invariant in checker.INVARIANTS),
                "// Serialize Deserialize",
                "/*",
                commented_tests,
                "*/",
            ]
        )
        comment_only_conformance = "\n".join(
            f"// fn {test_name}() {{}}" for test_name in checker.REQUIRED_CONFORMANCE_TESTS
        )

        original_impl = checker.IMPL
        original_mod = checker.MOD_RS
        original_conformance = checker.CONFORMANCE_TEST
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            impl_path = tmp / "control_evidence.rs"
            mod_path = tmp / "mod.rs"
            conformance_path = tmp / "control_policy_evidence_required.rs"
            impl_path.write_text(comment_only_impl, encoding="utf-8")
            mod_path.write_text("pub mod control_evidence;\n", encoding="utf-8")
            conformance_path.write_text(comment_only_conformance, encoding="utf-8")

            try:
                checker.IMPL = impl_path
                checker.MOD_RS = mod_path
                checker.CONFORMANCE_TEST = conformance_path
                result = checker.run_checks()
            finally:
                checker.IMPL = original_impl
                checker.MOD_RS = original_mod
                checker.CONFORMANCE_TEST = original_conformance

        checks = {check["check"]: check["pass"] for check in result["checks"]}
        self.assertTrue(checks["file: implementation"])
        self.assertTrue(checks["module registered in mod.rs"])
        self.assertFalse(checks["unit test count"])
        self.assertFalse(checks["Serialize/Deserialize derives"])
        self.assertEqual(result["test_count"], "0")

        expected_failures = []
        expected_failures.extend(f"type: {marker}" for marker in checker.REQUIRED_TYPES)
        expected_failures.extend(f"method: {marker}" for marker in checker.REQUIRED_METHODS)
        expected_failures.extend(f"event_code: {code}" for code in checker.EVENT_CODES)
        expected_failures.extend(f"invariant: {invariant}" for invariant in checker.INVARIANTS)
        expected_failures.extend(f"test: {test_name}" for test_name in checker.REQUIRED_TESTS)
        expected_failures.extend(
            f"conformance_test: {test_name}" for test_name in checker.REQUIRED_CONFORMANCE_TESTS
        )
        for check_name in expected_failures:
            self.assertIn(check_name, checks)
            self.assertFalse(checks[check_name], check_name)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = checker.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self):
        ok, checks = checker.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


class TestRequiredConstants(unittest.TestCase):
    def test_types_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TYPES), 7)

    def test_methods_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_METHODS), 10)

    def test_event_codes_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 5)

    def test_invariants_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TESTS), 45)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_checks()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_control_evidence.py"), "--json"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_human(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_control_evidence.py")],
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
