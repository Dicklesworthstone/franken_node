"""Unit tests for scripts/check_vef_verification_state.py (bd-8qlj)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_vef_verification_state.py"

spec = importlib.util.spec_from_file_location("check_vef_verification_state", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-8qlj")
        self.assertEqual(result["section"], "10.18")
        self.assertIn(result["verdict"], ("PASS", "FAIL"))
        self.assertEqual(result["failed"], result["total"] - result["passed"])
        self.assertEqual(result["total"], len(result["checks"]))

    def test_check_entries_shape(self) -> None:
        result = mod.run_all()
        for check in result["checks"]:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)
            self.assertIsInstance(check["check"], str)
            self.assertIsInstance(check["pass"], bool)
            self.assertIsInstance(check["detail"], str)

    def test_has_timestamp(self) -> None:
        result = mod.run_all()
        self.assertIn("timestamp", result)

    def test_total_checks_count(self) -> None:
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 45)


class TestVerdict(unittest.TestCase):
    def test_all_impl_checks_pass(self) -> None:
        result = mod.run_all()
        impl_checks = [c for c in result["checks"] if c["check"].startswith("impl_")]
        for c in impl_checks:
            self.assertTrue(c["pass"], f"FAIL: {c['check']}: {c['detail']}")


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS", self._failures(result))

    def test_self_test_shape(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["mode"], "self-test")
        self.assertGreaterEqual(result["total"], 8)
        self.assertEqual(result["failed"], result["total"] - result["passed"])

    @staticmethod
    def _failures(result: dict) -> str:
        return "\n".join(f"FAIL: {c['check']}: {c['detail']}" for c in result["checks"] if not c["pass"])


class TestCli(unittest.TestCase):
    def test_self_test_cli_exit_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_self_test_json_cli(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-8qlj")
        self.assertEqual(parsed["mode"], "self-test")

    def test_json_output_parseable(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-8qlj")
        self.assertIn("checks", parsed)


class TestConstants(unittest.TestCase):
    def test_bead_id(self) -> None:
        self.assertEqual(mod.BEAD_ID, "bd-8qlj")

    def test_section(self) -> None:
        self.assertEqual(mod.SECTION, "10.18")

    def test_symbol_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_SYMBOLS), 18)

    def test_risk_level_count(self) -> None:
        self.assertEqual(len(mod.RISK_LEVELS), 4)

    def test_event_code_count(self) -> None:
        self.assertEqual(len(mod.EVENT_CODES), 5)

    def test_error_code_count(self) -> None:
        self.assertEqual(len(mod.ERROR_CODES), 5)


if __name__ == "__main__":
    unittest.main()
