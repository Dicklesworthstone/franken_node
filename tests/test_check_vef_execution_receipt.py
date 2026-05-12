"""Unit tests for scripts/check_vef_execution_receipt.py (bd-p73r)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_vef_execution_receipt.py"

spec = importlib.util.spec_from_file_location("check_vef_execution_receipt", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-p73r")
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


class TestVerdict(unittest.TestCase):
    def test_verdict_pass(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failure_text(result))

    @staticmethod
    def _failure_text(result: dict) -> str:
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"FAIL: {c['check']}: {c['detail']}" for c in failures[:12])


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_self_test_shape(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["mode"], "self-test")
        self.assertGreaterEqual(result["total"], 6)
        self.assertEqual(result["failed"], result["total"] - result["passed"])


class TestCli(unittest.TestCase):
    def test_json_cli_output(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-p73r")
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
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                mod.SUMMARY = Path(temp_dir) / "missing-summary.md"
                result = mod.run_all()
                self.assertEqual(result["verdict"], "FAIL")
                failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
                self.assertIn("summary_exists", failed_checks)
            finally:
                mod.SUMMARY = original

    def test_vector_hash_mismatch_fails(self) -> None:
        original = mod.VECTORS
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                vector_copy = json.loads(original.read_text(encoding="utf-8"))
                vector_copy["vectors"][0]["expected_hash"] = (
                    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                )
                mutated_vectors = Path(temp_dir) / "vef_receipt_schema_vectors.json"
                mutated_vectors.write_text(json.dumps(vector_copy), encoding="utf-8")
                mod.VECTORS = mutated_vectors

                result = mod.run_all()

                self.assertEqual(result["verdict"], "FAIL")
                failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
                self.assertIn("vector_0_expected_hash_matches_canonical_bytes", failed_checks)
            finally:
                mod.VECTORS = original


if __name__ == "__main__":
    unittest.main()
