"""Unit tests for scripts/check_vef_perf_budget_gate.py (bd-ufk5)."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_vef_perf_budget_gate.py"


def _load_checker():
    """Dynamically load the checker module."""
    spec = importlib.util.spec_from_file_location("checker", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSelfTest(TestCase):
    """Verify the self-test mode of the checker script."""

    def test_self_test_passes(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, f"self-test failed: {result.stdout}")
        data = json.loads(result.stdout)
        self.assertTrue(data["all_passed"])
        self.assertGreater(data["total"], 0)

    def test_self_test_check_counts(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        data = json.loads(result.stdout)
        self.assertGreaterEqual(data["total"], 10)
        self.assertEqual(data["passed"], data["total"])


class TestJsonOutput(TestCase):
    """Verify JSON output format of the checker."""

    def test_json_mode_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        data = json.loads(result.stdout)
        self.assertIn("bead_id", data)
        self.assertEqual(data["bead_id"], "bd-ufk5")
        self.assertEqual(data["section"], "10.18")
        self.assertIn("passed", data)
        self.assertIn("total", data)
        self.assertIn("checks", data)
        self.assertIsInstance(data["checks"], list)

    def test_all_checks_have_required_fields(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        data = json.loads(result.stdout)
        for check in data["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIsInstance(check["passed"], bool)


class TestCheckerModule(TestCase):
    """Test the checker module's internal functions."""

    def setUp(self):
        self.mod = _load_checker()
        # Reset state
        self.mod.ALL_CHECKS.clear()
        self.mod.RESULTS.clear()

    def test_required_types_are_comprehensive(self):
        self.assertGreaterEqual(len(self.mod.REQUIRED_TYPES), 10)
        self.assertIn("pub struct VefPerfBudgetGate", self.mod.REQUIRED_TYPES)
        self.assertIn("pub enum VefOperation", self.mod.REQUIRED_TYPES)

    def test_required_event_codes_are_comprehensive(self):
        self.assertEqual(len(self.mod.REQUIRED_EVENT_CODES), 6)
        self.assertIn("VEF-PERF-001", self.mod.REQUIRED_EVENT_CODES)
        self.assertIn("VEF-PERF-ERR-001", self.mod.REQUIRED_EVENT_CODES)

    def test_required_operations_count(self):
        self.assertEqual(len(self.mod.REQUIRED_OPERATIONS), 7)

    def test_required_modes_count(self):
        self.assertEqual(len(self.mod.REQUIRED_MODES), 3)

    def test_required_functions_are_comprehensive(self):
        self.assertGreaterEqual(len(self.mod.REQUIRED_FUNCTIONS), 5)
        self.assertIn("fn evaluate", self.mod.REQUIRED_FUNCTIONS)
        self.assertIn("fn record_baseline", self.mod.REQUIRED_FUNCTIONS)

    def test_required_invariants_count(self):
        self.assertEqual(len(self.mod.REQUIRED_INVARIANTS_SPEC), 6)

    def test_record_function(self):
        self.mod.record("test_check", True, "detail")
        self.assertEqual(len(self.mod.ALL_CHECKS), 1)
        self.assertTrue(self.mod.ALL_CHECKS[0]["passed"])

    def test_file_contains_positive(self):
        # SCRIPT itself contains the string "bd-ufk5"
        self.assertTrue(self.mod.file_contains(SCRIPT, "bd-ufk5"))

    def test_file_contains_negative(self):
        self.assertFalse(
            self.mod.file_contains(SCRIPT, "DEFINITELY_NOT_IN_FILE_xyzzy")
        )

    def test_file_contains_missing_file(self):
        self.assertFalse(
            self.mod.file_contains(Path("/nonexistent/file.rs"), "anything")
        )


class TestVerificationPasses(TestCase):
    """Verify that the checker reports all checks passing."""

    def test_all_checks_pass(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        data = json.loads(result.stdout)
        failed = [c for c in data["checks"] if not c["passed"]]
        self.assertEqual(
            len(failed),
            0,
            f"Failed checks: {json.dumps(failed, indent=2)}",
        )

    def test_sufficient_rust_tests(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        data = json.loads(result.stdout)
        self.assertGreaterEqual(
            data.get("rust_test_count", 0),
            15,
            "Need at least 15 Rust unit tests",
        )


if __name__ == "__main__":
    main()
