#!/usr/bin/env python3
"""Unit tests for scripts/check_gate_api.py"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_gate_api as checker


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        checker.self_test()


class TestFilesExist(unittest.TestCase):
    def test_two_files(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        checks = [r for r in checker.RESULTS if r["name"].startswith("file_exists:")]
        self.assertEqual(len(checks), 2)

    def test_spec_found(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        c = [r for r in checker.RESULTS if r["name"] == "file_exists:spec"][0]
        self.assertTrue(c["pass"])

    def test_policy_found(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        c = [r for r in checker.RESULTS if r["name"] == "file_exists:policy"][0]
        self.assertTrue(c["pass"])


class TestApiSurfaces(unittest.TestCase):
    def test_five_surfaces(self):
        checker.RESULTS.clear()
        checker.check_api_surfaces()
        checks = [r for r in checker.RESULTS if r["name"].startswith("api:")]
        self.assertEqual(len(checks), 5)


class TestCompatibilityModes(unittest.TestCase):
    def test_three_modes(self):
        checker.RESULTS.clear()
        checker.check_compatibility_modes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("mode:")]
        self.assertEqual(len(checks), 3)


class TestEventCodes(unittest.TestCase):
    def test_four_codes(self):
        checker.RESULTS.clear()
        checker.check_event_codes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("event_code:")]
        self.assertEqual(len(checks), 4)


class TestInvariants(unittest.TestCase):
    def test_four_invariants(self):
        checker.RESULTS.clear()
        checker.check_invariants()
        checks = [r for r in checker.RESULTS if r["name"].startswith("invariant:")]
        self.assertEqual(len(checks), 4)


class TestPolicyContracts(unittest.TestCase):
    def test_four_keywords(self):
        checker.RESULTS.clear()
        checker.check_policy_contracts()
        checks = [r for r in checker.RESULTS if r["name"].startswith("policy:")]
        self.assertEqual(len(checks), 4)


class TestProperties(unittest.TestCase):
    def test_two_properties(self):
        checker.RESULTS.clear()
        checker.check_properties()
        checks = [r for r in checker.RESULTS if r["name"].startswith("property:")]
        self.assertEqual(len(checks), 2)


class TestPerformance(unittest.TestCase):
    def test_three_keywords(self):
        checker.RESULTS.clear()
        checker.check_performance()
        checks = [r for r in checker.RESULTS if r["name"].startswith("perf:")]
        self.assertEqual(len(checks), 3)


class TestRunAll(unittest.TestCase):
    def test_returns_dict(self):
        result = checker.run_all()
        self.assertIsInstance(result, dict)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-137")

    def test_math(self):
        result = checker.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])

    def test_verdict_pass(self):
        result = checker.run_all()
        self.assertEqual(result["verdict"], "PASS")


class TestMissingFiles(unittest.TestCase):
    def test_spec_missing(self):
        with patch.object(checker, "SPEC_PATH", Path("/nonexistent/spec.md")):
            checker.RESULTS.clear()
            checker.check_files_exist()
            c = [r for r in checker.RESULTS if r["name"] == "file_exists:spec"][0]
            self.assertFalse(c["pass"])

    def test_policy_missing(self):
        with patch.object(checker, "POLICY_PATH", Path("/nonexistent/policy.md")):
            checker.RESULTS.clear()
            checker.check_files_exist()
            c = [r for r in checker.RESULTS if r["name"] == "file_exists:policy"][0]
            self.assertFalse(c["pass"])


class TestJsonOutput(unittest.TestCase):
    def test_json_flag(self):
        result = subprocess.run(
            [sys.executable, "scripts/check_gate_api.py", "--json"],
            capture_output=True, text=True, cwd=str(checker.ROOT),
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["bead_id"], "bd-137")


class TestSafeRel(unittest.TestCase):
    def test_inside_root(self):
        p = checker.ROOT / "foo.md"
        self.assertEqual(checker._safe_rel(p), "foo.md")

    def test_outside_root(self):
        p = Path("/tmp/foo.md")
        self.assertEqual(checker._safe_rel(p), "/tmp/foo.md")


if __name__ == "__main__":
    unittest.main()
