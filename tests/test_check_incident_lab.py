"""Unit tests for scripts/check_incident_lab.py."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_incident_lab.py"

spec = importlib.util.spec_from_file_location("check_incident_lab", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestVerdict(unittest.TestCase):
    def test_gate_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["passed"]]
        return "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failures[:10])


class TestResultShape(unittest.TestCase):
    def test_required_fields(self):
        result = mod.run_all()
        for key in [
            "schema_version",
            "bead_id",
            "section",
            "verdict",
            "checks",
            "event_codes",
            "error_codes",
            "invariants",
        ]:
            self.assertIn(key, result)

    def test_bead_and_section(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-383z")
        self.assertEqual(result["section"], "10.17")

    def test_schema_version(self):
        result = mod.run_all()
        self.assertTrue(result["schema_version"].startswith("incident-lab-"))


class TestChecks(unittest.TestCase):
    def test_minimum_check_count(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 30)

    def test_all_checks_have_keys(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)

    def test_no_failures(self):
        result = mod.run_all()
        self.assertEqual(result["failed"], 0, self._failing(result))

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["passed"]]
        return "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failures[:10])


class TestEventCodes(unittest.TestCase):
    def test_event_code_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_EVENT_CODES), 6)

    def test_event_codes_start_with_ilab(self):
        for code in mod.REQUIRED_EVENT_CODES:
            self.assertTrue(code.startswith("ILAB_"), f"Bad event code: {code}")


class TestErrorCodes(unittest.TestCase):
    def test_error_code_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_ERROR_CODES), 6)

    def test_error_codes_start_with_err(self):
        for code in mod.REQUIRED_ERROR_CODES:
            self.assertTrue(code.startswith("ERR_ILAB_"), f"Bad error code: {code}")


class TestInvariants(unittest.TestCase):
    def test_invariant_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_INVARIANTS), 5)

    def test_invariants_start_with_inv(self):
        for inv in mod.REQUIRED_INVARIANTS:
            self.assertTrue(inv.startswith("INV-ILAB-"), f"Bad invariant: {inv}")


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        st = mod.self_test()
        self.assertEqual(st["verdict"], "PASS")

    def test_self_test_has_checks(self):
        st = mod.self_test()
        self.assertIn("checks", st)
        self.assertGreaterEqual(len(st["checks"]), 5)


class TestCli(unittest.TestCase):
    def test_json_output_parseable(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-383z")

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
