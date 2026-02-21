"""Unit tests for scripts/check_harness_throughput.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

# Import the check module via importlib to avoid naming collisions.
spec = importlib.util.spec_from_file_location(
    "check_harness_throughput",
    ROOT / "scripts" / "check_harness_throughput.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestSpecExists(TestCase):
    def test_spec_file_present(self) -> None:
        mod.RESULTS = []
        result = mod.check_spec_exists()
        self.assertTrue(result["pass"])
        self.assertIn("exists", result["detail"])

    def test_spec_file_missing(self) -> None:
        mod.RESULTS = []
        with patch.object(mod, "SPEC_PATH", ROOT / "nonexistent" / "file.md"):
            result = mod.check_spec_exists()
        self.assertFalse(result["pass"])
        self.assertIn("missing", result["detail"])


class TestPolicyExists(TestCase):
    def test_policy_file_present(self) -> None:
        mod.RESULTS = []
        result = mod.check_policy_exists()
        self.assertTrue(result["pass"])
        self.assertIn("exists", result["detail"])

    def test_policy_file_missing(self) -> None:
        mod.RESULTS = []
        with patch.object(mod, "POLICY_PATH", ROOT / "nonexistent" / "file.md"):
            result = mod.check_policy_exists()
        self.assertFalse(result["pass"])


class TestSpecKeywords(TestCase):
    def test_streaming_keyword(self) -> None:
        mod.RESULTS = []
        result = mod.check_spec_keyword_streaming()
        self.assertTrue(result["pass"])

    def test_normalization_keyword(self) -> None:
        mod.RESULTS = []
        result = mod.check_spec_keyword_normalization()
        self.assertTrue(result["pass"])

    def test_spill_to_disk_keyword(self) -> None:
        mod.RESULTS = []
        result = mod.check_spec_keyword_spill_to_disk()
        self.assertTrue(result["pass"])

    def test_512mb_keyword(self) -> None:
        mod.RESULTS = []
        result = mod.check_spec_keyword_512mb()
        self.assertTrue(result["pass"])

    def test_20_percent_keyword(self) -> None:
        mod.RESULTS = []
        result = mod.check_spec_keyword_20_percent()
        self.assertTrue(result["pass"])


class TestEventCodes(TestCase):
    def test_all_event_codes_present(self) -> None:
        mod.RESULTS = []
        results = mod.check_event_codes()
        self.assertEqual(len(results), 4)
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']} should pass")

    def test_event_codes_with_missing_spec(self) -> None:
        mod.RESULTS = []
        with patch.object(mod, "SPEC_PATH", ROOT / "nonexistent.md"):
            results = mod.check_event_codes()
        for r in results:
            self.assertFalse(r["pass"])


class TestInvariants(TestCase):
    def test_all_invariants_present(self) -> None:
        mod.RESULTS = []
        results = mod.check_invariants()
        self.assertEqual(len(results), 4)
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']} should pass")


class TestOptimizationPhases(TestCase):
    def test_phases_present(self) -> None:
        mod.RESULTS = []
        result = mod.check_optimization_phases()
        self.assertTrue(result["pass"])
        self.assertIn("4 phases", result["detail"])


class TestBenchmarkTargets(TestCase):
    def test_targets_present(self) -> None:
        mod.RESULTS = []
        result = mod.check_benchmark_targets()
        self.assertTrue(result["pass"])


class TestMemoryCeiling(TestCase):
    def test_ceiling_documented(self) -> None:
        mod.RESULTS = []
        result = mod.check_memory_ceiling()
        self.assertTrue(result["pass"])


class TestWarmPool(TestCase):
    def test_warm_pool_documented(self) -> None:
        mod.RESULTS = []
        result = mod.check_warm_pool()
        self.assertTrue(result["pass"])


class TestStreamingNormalization(TestCase):
    def test_normalization_rules(self) -> None:
        mod.RESULTS = []
        result = mod.check_streaming_normalization_rules()
        self.assertTrue(result["pass"])


class TestPolicyEventCodes(TestCase):
    def test_policy_has_event_codes(self) -> None:
        mod.RESULTS = []
        result = mod.check_policy_event_codes()
        self.assertTrue(result["pass"])


class TestRunAll(TestCase):
    def test_run_all_structure(self) -> None:
        report = mod.run_all()
        self.assertEqual(report["bead_id"], "bd-38m")
        self.assertEqual(report["section"], "10.6")
        self.assertIn("verdict", report)
        self.assertIn("total", report)
        self.assertIn("passed", report)
        self.assertIn("failed", report)
        self.assertIn("checks", report)
        self.assertIsInstance(report["checks"], list)
        self.assertGreater(len(report["checks"]), 10)

    def test_run_all_passes(self) -> None:
        report = mod.run_all()
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["passed"], report["total"])


class TestSelfTest(TestCase):
    def test_self_test_returns_true(self) -> None:
        self.assertTrue(mod.self_test())


class TestSafeRelative(TestCase):
    def test_path_inside_root(self) -> None:
        p = mod.ROOT / "docs" / "test.md"
        self.assertEqual(mod._safe_relative(p), "docs/test.md")

    def test_path_outside_root(self) -> None:
        p = Path("/tmp/unrelated/file.md")
        result = mod._safe_relative(p)
        self.assertEqual(result, "/tmp/unrelated/file.md")


class TestJsonOutput(TestCase):
    def test_json_flag_produces_valid_json(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_harness_throughput.py"), "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["bead_id"], "bd-38m")
        self.assertEqual(data["verdict"], "PASS")


if __name__ == "__main__":
    main()
