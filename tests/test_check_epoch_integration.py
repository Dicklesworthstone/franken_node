"""Tests for scripts/check_epoch_integration.py (bd-2gr)."""

import json
import runpy
import subprocess
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_epoch_integration.py"

mod = types.SimpleNamespace(**runpy.run_path(str(SCRIPT)))


def _run_json() -> dict:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return json.JSONDecoder().decode(result.stdout)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())

    def test_read_missing_file_returns_empty_string(self):
        self.assertEqual(mod._read(ROOT / "missing-epoch-integration-file.rs"), "")


class TestJsonOutput(unittest.TestCase):
    def test_json_output_shape(self):
        data = _run_json()
        self.assertEqual(data["bead_id"], "bd-2gr")
        self.assertEqual(data["section"], "10.11")
        self.assertIsInstance(data["checks"], list)

    def test_verdict_field(self):
        data = _run_json()
        self.assertIn(data["verdict"], ("PASS", "FAIL"))

    def test_checks_have_required_fields(self):
        data = _run_json()
        for check in data["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_minimum_check_count(self):
        data = _run_json()
        self.assertGreaterEqual(len(data["checks"]), 40)

    def test_cli_self_test(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("self_test passed", result.stdout)


class TestConstants(unittest.TestCase):
    def test_guard_event_count(self):
        self.assertEqual(len(mod.EVENT_CODES_GUARD), 6)

    def test_transition_event_count(self):
        self.assertEqual(len(mod.EVENT_CODES_TRANSITION), 5)

    def test_error_code_count(self):
        self.assertGreaterEqual(len(mod.ERROR_CODES), 6)

    def test_invariant_count(self):
        self.assertEqual(len(mod.INVARIANTS), 6)


class TestIndividualChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {c["name"]: c for c in mod.run_all()["checks"]}

    def test_spec_exists(self):
        self.assertTrue(self.results["spec_exists"]["passed"])

    def test_guard_module_exists(self):
        self.assertTrue(self.results["guard_module_exists"]["passed"])

    def test_transition_module_exists(self):
        self.assertTrue(self.results["transition_module_exists"]["passed"])

    def test_runtime_wiring_guard(self):
        self.assertTrue(self.results["runtime_mod_wiring_guard"]["passed"])

    def test_runtime_wiring_transition(self):
        self.assertTrue(self.results["runtime_mod_wiring_transition"]["passed"])

    def test_fail_closed_path(self):
        self.assertTrue(self.results["fail_closed_unavailable_path"]["passed"])

    def test_fail_closed_latency_test(self):
        self.assertTrue(self.results["fail_closed_latency_test"]["passed"])

    def test_creation_epoch_private(self):
        self.assertTrue(self.results["artifact_creation_epoch_private"]["passed"])

    def test_creation_epoch_getter(self):
        self.assertTrue(self.results["artifact_creation_epoch_getter"]["passed"])

    def test_creation_epoch_no_setter(self):
        self.assertTrue(self.results["artifact_creation_epoch_no_setter"]["passed"])

    def test_key_integration(self):
        self.assertTrue(self.results["epoch_key_signing_integration"]["passed"])

    def test_transition_barrier_integration(self):
        self.assertTrue(self.results["transition_barrier_integration"]["passed"])

    def test_split_brain_guard(self):
        self.assertTrue(self.results["split_brain_guard"]["passed"])

    def test_transition_sequence(self):
        self.assertTrue(self.results["transition_sequence_apis"]["passed"])

    def test_abort_timeout_api(self):
        self.assertTrue(self.results["abort_timeout_api"]["passed"])

    def test_history_metadata(self):
        self.assertTrue(self.results["transition_history_metadata"]["passed"])

    def test_integration_five_services(self):
        self.assertTrue(self.results["integration_test_five_services"]["passed"])

    def test_integration_timeout_abort(self):
        self.assertTrue(self.results["integration_test_timeout_abort"]["passed"])

    def test_monotonicity_test(self):
        self.assertTrue(self.results["unit_test_monotonicity"]["passed"])

    def test_guard_test_count(self):
        self.assertTrue(self.results["guard_test_count"]["passed"])

    def test_transition_test_count(self):
        self.assertTrue(self.results["transition_test_count"]["passed"])


class TestOverall(unittest.TestCase):
    def test_all_checks_pass(self):
        failed = [c for c in mod.run_all()["checks"] if not c["passed"]]
        self.assertEqual(len(failed), 0, f"Failed checks: {[c['name'] for c in failed]}")

    def test_verdict_is_pass(self):
        data = _run_json()
        self.assertEqual(data["verdict"], "PASS")

    def test_human_output_contains_pass(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bd-2gr", result.stdout)
        self.assertIn("PASS", result.stdout)
