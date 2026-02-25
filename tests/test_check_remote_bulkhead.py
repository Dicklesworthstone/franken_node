"""Tests for scripts/check_remote_bulkhead.py (bd-v4l0)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_remote_bulkhead.py"

spec = importlib.util.spec_from_file_location("check_remote_bulkhead", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestChecksStructure(unittest.TestCase):
    """Verify _checks() returns well-formed results."""

    def setUp(self):
        self.results = module._checks()
        self.by_name = {r["check"]: r for r in self.results}

    def test_checks_returns_list(self):
        self.assertIsInstance(self.results, list)
        self.assertGreater(len(self.results), 0)

    def test_all_checks_have_keys(self):
        for r in self.results:
            self.assertIn("check", r)
            self.assertIn("passed", r)
            self.assertIn("detail", r)
            self.assertIsInstance(r["check"], str)
            self.assertIsInstance(r["passed"], bool)
            self.assertIsInstance(r["detail"], str)

    def test_all_checks_pass(self):
        failed = [r for r in self.results if not r["passed"]]
        self.assertEqual(
            len(failed),
            0,
            f"Failed checks: {[r['check'] for r in failed]}",
        )


class TestIndividualChecks(unittest.TestCase):
    """Verify each named check passes."""

    def setUp(self):
        self.results = module._checks()
        self.by_name = {r["check"]: r for r in self.results}

    def test_source_exists(self):
        self.assertTrue(self.by_name["SOURCE_EXISTS"]["passed"])

    def test_event_codes(self):
        r = self.by_name["EVENT_CODES"]
        self.assertTrue(r["passed"], r["detail"])

    def test_event_codes_module(self):
        r = self.by_name["EVENT_CODES_MODULE"]
        self.assertTrue(r["passed"], r["detail"])

    def test_error_codes(self):
        r = self.by_name["ERROR_CODES"]
        self.assertTrue(r["passed"], r["detail"])

    def test_core_types(self):
        r = self.by_name["CORE_TYPES"]
        self.assertTrue(r["passed"], r["detail"])

    def test_remotecap_gating(self):
        r = self.by_name["REMOTECAP_GATING"]
        self.assertTrue(r["passed"], r["detail"])

    def test_drain_mode(self):
        r = self.by_name["DRAIN_MODE"]
        self.assertTrue(r["passed"], r["detail"])

    def test_latency_tracking(self):
        r = self.by_name["LATENCY_TRACKING"]
        self.assertTrue(r["passed"], r["detail"])

    def test_backpressure_policy(self):
        r = self.by_name["BACKPRESSURE_POLICY"]
        self.assertTrue(r["passed"], r["detail"])

    def test_core_operations(self):
        r = self.by_name["CORE_OPERATIONS"]
        self.assertTrue(r["passed"], r["detail"])

    def test_permit_lifecycle(self):
        r = self.by_name["PERMIT_LIFECYCLE"]
        self.assertTrue(r["passed"], r["detail"])

    def test_queue_timeout(self):
        r = self.by_name["QUEUE_TIMEOUT"]
        self.assertTrue(r["passed"], r["detail"])

    def test_serde_derives(self):
        r = self.by_name["SERDE_DERIVES"]
        self.assertTrue(r["passed"], r["detail"])

    def test_test_coverage(self):
        r = self.by_name["TEST_COVERAGE"]
        self.assertTrue(r["passed"], r["detail"])

    def test_spec_contract(self):
        r = self.by_name["SPEC_CONTRACT"]
        self.assertTrue(r["passed"], r["detail"])


class TestSelfTest(unittest.TestCase):
    """Verify self_test() function works."""

    def test_self_test_passes(self):
        self.assertTrue(module.self_test())


class TestCliOutput(unittest.TestCase):
    """Verify CLI modes produce expected output."""

    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["bead"], "bd-v4l0")
        self.assertEqual(data["section"], "10.14")
        self.assertEqual(data["title"], "Remote Bulkhead")
        self.assertIn("verdict", data)
        self.assertIn("passed", data)
        self.assertIn("total", data)
        self.assertIn("checks", data)
        self.assertIsInstance(data["checks"], list)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["passed"], data["total"])

    def test_self_test_cli(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("self_test:", result.stdout)
        self.assertIn("PASS", result.stdout)

    def test_human_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bd-v4l0", result.stdout)
        self.assertIn("PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
