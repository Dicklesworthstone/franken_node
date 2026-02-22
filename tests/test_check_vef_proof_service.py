"""Unit tests for scripts/check_vef_proof_service.py (bd-1u8m)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_vef_proof_service.py"

spec = importlib.util.spec_from_file_location("check_vef_proof_service", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-1u8m")
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


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["mode"], "self-test")
        self.assertEqual(result["failed"], result["total"] - result["passed"])
        self.assertGreaterEqual(result["total"], 6)


class TestCli(unittest.TestCase):
    def test_json_cli_output(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertIn(proc.returncode, (0, 1), proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-1u8m")
        self.assertIn("checks", parsed)

    def test_self_test_cli_exit_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


class TestFailureInjection(unittest.TestCase):
    def test_missing_summary_fails(self) -> None:
        original = mod.SUMMARY
        with tempfile.TemporaryDirectory() as tmp:
            mod.SUMMARY = Path(tmp) / "missing-summary.md"
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [entry["check"] for entry in result["checks"] if not entry["pass"]]
            self.assertIn("summary_exists", failed_checks)
        mod.SUMMARY = original


if __name__ == "__main__":
    unittest.main()
