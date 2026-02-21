#!/usr/bin/env python3
"""Unit tests for scripts/check_scanner_throughput.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

# Import the check module dynamically
_spec = importlib.util.spec_from_file_location(
    "check_scanner_throughput",
    ROOT / "scripts" / "check_scanner_throughput.py",
)
_mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _mod
_spec.loader.exec_module(_mod)

checker = _mod


class TestSpecExists(unittest.TestCase):
    def test_spec_file_exists(self):
        checker.RESULTS = []
        result = checker.check_spec_exists()
        self.assertTrue(result["pass"])
        self.assertIn("exists:", result["detail"])

    def test_spec_missing(self):
        checker.RESULTS = []
        with patch.object(checker, "SPEC", Path("/nonexistent/spec.md")):
            result = checker.check_spec_exists()
        self.assertFalse(result["pass"])
        self.assertIn("missing:", result["detail"])


class TestPolicyExists(unittest.TestCase):
    def test_policy_file_exists(self):
        checker.RESULTS = []
        result = checker.check_policy_exists()
        self.assertTrue(result["pass"])
        self.assertIn("exists:", result["detail"])

    def test_policy_missing(self):
        checker.RESULTS = []
        with patch.object(checker, "POLICY", Path("/nonexistent/policy.md")):
            result = checker.check_policy_exists()
        self.assertFalse(result["pass"])


class TestSpecKeywords(unittest.TestCase):
    def test_incremental_keyword(self):
        checker.RESULTS = []
        result = checker.check_spec_keyword("incremental")
        self.assertTrue(result["pass"])

    def test_parallel_keyword(self):
        checker.RESULTS = []
        result = checker.check_spec_keyword("parallel")
        self.assertTrue(result["pass"])

    def test_deterministic_keyword(self):
        checker.RESULTS = []
        result = checker.check_spec_keyword("deterministic")
        self.assertTrue(result["pass"])

    def test_cache_keyword(self):
        checker.RESULTS = []
        result = checker.check_spec_keyword("cache")
        self.assertTrue(result["pass"])

    def test_ttl_keyword(self):
        checker.RESULTS = []
        result = checker.check_spec_keyword("TTL")
        self.assertTrue(result["pass"])

    def test_hash_keyword(self):
        checker.RESULTS = []
        result = checker.check_spec_keyword("hash")
        self.assertTrue(result["pass"])

    def test_missing_keyword(self):
        checker.RESULTS = []
        result = checker.check_spec_keyword("ZZNONEXISTENTZZ")
        self.assertFalse(result["pass"])

    def test_keyword_with_missing_spec(self):
        checker.RESULTS = []
        with patch.object(checker, "SPEC", Path("/nonexistent/spec.md")):
            result = checker.check_spec_keyword("cache")
        self.assertFalse(result["pass"])
        self.assertIn("spec file missing", result["detail"])


class TestEventCodes(unittest.TestCase):
    def test_all_event_codes_present(self):
        for code in checker.EVENT_CODES:
            checker.RESULTS = []
            result = checker.check_event_code(code)
            self.assertTrue(result["pass"], f"Event code {code} not found")

    def test_event_code_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 4)

    def test_missing_event_code(self):
        checker.RESULTS = []
        result = checker.check_event_code("OMS-999")
        self.assertFalse(result["pass"])


class TestInvariants(unittest.TestCase):
    def test_all_invariants_present(self):
        for inv in checker.INVARIANTS:
            checker.RESULTS = []
            result = checker.check_invariant(inv)
            self.assertTrue(result["pass"], f"Invariant {inv} not found")

    def test_invariant_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_missing_invariant(self):
        checker.RESULTS = []
        result = checker.check_invariant("INV-OMS-FAKE")
        self.assertFalse(result["pass"])


class TestPolicyStrategies(unittest.TestCase):
    def test_all_strategies_present(self):
        for strategy in checker.OPTIMIZATION_STRATEGIES:
            checker.RESULTS = []
            result = checker.check_policy_strategy(strategy)
            self.assertTrue(result["pass"], f"Strategy '{strategy}' not found")

    def test_strategy_count(self):
        self.assertEqual(len(checker.OPTIMIZATION_STRATEGIES), 3)


class TestBenchmarkTargets(unittest.TestCase):
    def test_all_targets_present(self):
        for target in checker.BENCHMARK_TARGETS:
            checker.RESULTS = []
            result = checker.check_policy_benchmark_target(target)
            self.assertTrue(result["pass"], f"Target '{target}' not found")

    def test_target_count(self):
        self.assertEqual(len(checker.BENCHMARK_TARGETS), 4)


class TestQuantitativeTargets(unittest.TestCase):
    def test_targets_present(self):
        checker.RESULTS = []
        result = checker.check_spec_quantitative_targets()
        self.assertTrue(result["pass"])
        self.assertIn("10% threshold", result["detail"])
        self.assertIn("3.0x speedup", result["detail"])
        self.assertIn("7-day TTL", result["detail"])


class TestCachePath(unittest.TestCase):
    def test_cache_path_documented(self):
        checker.RESULTS = []
        result = checker.check_spec_cache_path()
        self.assertTrue(result["pass"])


class TestClearCacheFlag(unittest.TestCase):
    def test_clear_cache_documented(self):
        checker.RESULTS = []
        result = checker.check_spec_clear_cache_flag()
        self.assertTrue(result["pass"])


class TestCacheVersioning(unittest.TestCase):
    def test_cache_versioning_documented(self):
        checker.RESULTS = []
        result = checker.check_policy_cache_versioning()
        self.assertTrue(result["pass"])


class TestWorkersFlag(unittest.TestCase):
    def test_workers_documented(self):
        checker.RESULTS = []
        result = checker.check_policy_workers_flag()
        self.assertTrue(result["pass"])


class TestSyntheticFixture(unittest.TestCase):
    def test_fixture_documented(self):
        checker.RESULTS = []
        result = checker.check_policy_synthetic_fixture()
        self.assertTrue(result["pass"])


class TestRunAll(unittest.TestCase):
    def test_run_all_structure(self):
        report = checker.run_all()
        self.assertIn("bead_id", report)
        self.assertIn("verdict", report)
        self.assertIn("total", report)
        self.assertIn("passed", report)
        self.assertIn("failed", report)
        self.assertIn("checks", report)
        self.assertEqual(report["bead_id"], "bd-2q5")
        self.assertEqual(report["section"], "10.6")

    def test_run_all_passes(self):
        report = checker.run_all()
        self.assertEqual(report["verdict"], "PASS")
        self.assertTrue(report["overall_pass"])

    def test_run_all_counts_consistent(self):
        report = checker.run_all()
        self.assertEqual(report["total"], report["passed"] + report["failed"])
        self.assertEqual(report["total"], len(report["checks"]))

    def test_run_all_check_count(self):
        report = checker.run_all()
        # 2 existence + 6 keywords + 4 event codes + 4 invariants +
        # 3 strategies + 4 benchmark targets + 1 quantitative + 1 cache path +
        # 1 clear-cache + 1 cache versioning + 1 workers + 1 synthetic = 29
        self.assertGreaterEqual(report["total"], 15)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = checker.self_test()
        self.assertTrue(ok)
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)

    def test_self_test_returns_checks(self):
        ok, checks = checker.self_test()
        for c in checks:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        report = checker.run_all()
        json_str = json.dumps(report)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "check_scanner_throughput.py"),
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["bead_id"], "bd-2q5")

    def test_cli_human(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "check_scanner_throughput.py"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        self.assertIn("PASS", proc.stdout)

    def test_cli_self_test(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "check_scanner_throughput.py"),
                "--self-test",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        self.assertIn("self_test:", proc.stdout)

    def test_cli_self_test_json(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "check_scanner_throughput.py"),
                "--self-test",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"])
        self.assertIn("checks", data)


class TestSafeRel(unittest.TestCase):
    def test_path_under_root(self):
        p = ROOT / "some" / "file.txt"
        result = checker._safe_rel(p)
        self.assertEqual(result, "some/file.txt")

    def test_path_outside_root(self):
        p = Path("/tmp/mock/file.txt")
        result = checker._safe_rel(p)
        self.assertEqual(result, "/tmp/mock/file.txt")


class TestCheckHelper(unittest.TestCase):
    def test_check_pass(self):
        checker.RESULTS = []
        result = checker._check("test_name", True, "ok")
        self.assertTrue(result["pass"])
        self.assertEqual(result["check"], "test_name")
        self.assertEqual(result["detail"], "ok")

    def test_check_fail(self):
        checker.RESULTS = []
        result = checker._check("test_name", False, "bad")
        self.assertFalse(result["pass"])

    def test_check_default_detail(self):
        checker.RESULTS = []
        result = checker._check("test_name", True)
        self.assertEqual(result["detail"], "found")
        checker.RESULTS = []
        result = checker._check("test_name", False)
        self.assertEqual(result["detail"], "NOT FOUND")

    def test_check_appends_to_results(self):
        checker.RESULTS = []
        checker._check("a", True)
        checker._check("b", False)
        self.assertEqual(len(checker.RESULTS), 2)


if __name__ == "__main__":
    unittest.main()
