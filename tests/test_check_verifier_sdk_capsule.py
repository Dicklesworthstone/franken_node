"""Unit tests for scripts/check_verifier_sdk_capsule.py (bd-nbwo)."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_verifier_sdk_capsule.py"

spec = importlib.util.spec_from_file_location("check_verifier_sdk_capsule", SCRIPT_PATH)
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
            "schema_version", "bead_id", "section", "verdict",
            "checks", "event_codes", "error_codes", "invariants",
            "capsule_contract", "events", "summary", "timestamp",
        ]:
            self.assertIn(key, result)

    def test_bead_and_section(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-nbwo")
        self.assertEqual(result["section"], "10.17")

    def test_schema_version(self):
        result = mod.run_all()
        self.assertEqual(result["schema_version"], "verifier-sdk-capsule-v1.0")


class TestChecks(unittest.TestCase):
    def test_minimum_check_count(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 25)

    def test_all_checks_have_keys(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)

    def test_no_failures(self):
        result = mod.run_all()
        failures = [c for c in result["checks"] if not c["passed"]]
        self.assertEqual(len(failures), 0,
                         "\n".join(f"FAIL: {c['check']}: {c['detail']}" for c in failures[:10]))


class TestCapsuleContract(unittest.TestCase):
    def test_contract_present(self):
        result = mod.run_all()
        contract = result["capsule_contract"]
        self.assertTrue(contract["capsule_replay_deterministic"])
        self.assertTrue(contract["no_privileged_access"])
        self.assertTrue(contract["schema_versioned"])
        self.assertTrue(contract["signature_bound"])
        self.assertTrue(contract["structural_only_posture_explicit"])

    def test_package_metadata_checks_present(self):
        result = mod.run_all()
        check_names = {check["check"] for check in result["checks"]}
        self.assertIn("SDK package metadata marks structural-only posture", check_names)
        self.assertIn("SDK package metadata avoids signed-capsule overclaim", check_names)


class TestEvents(unittest.TestCase):
    def test_events_present(self):
        result = mod.run_all()
        self.assertIsInstance(result["events"], list)
        self.assertGreater(len(result["events"]), 0)

    def test_events_have_codes(self):
        result = mod.run_all()
        codes = [e["code"] for e in result["events"]]
        for expected in mod.REQUIRED_EVENT_CODES:
            self.assertIn(expected, codes)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        st = mod.self_test()
        self.assertEqual(st["verdict"], "PASS",
                         f"Failures: {[c for c in st['checks'] if not c['passed']]}")


class TestCli(unittest.TestCase):
    def test_json_output_parseable(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-nbwo")

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
