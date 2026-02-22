"""Unit tests for scripts/check_proof_verifier.py (bd-1o4v)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_proof_verifier.py"

spec = importlib.util.spec_from_file_location("check_proof_verifier", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-1o4v")
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
        self.assertIsInstance(result["timestamp"], str)

    def test_check_count_reasonable(self) -> None:
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 80, "should have at least 80 checks")


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
        self.assertGreaterEqual(result["total"], 10)
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
        self.assertEqual(parsed["bead_id"], "bd-1o4v")
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

    def test_plain_cli_output(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertIn("[bd-1o4v]", proc.stdout)
        self.assertIn("PASS", proc.stdout)


class TestFailureInjection(unittest.TestCase):
    def test_missing_summary_fails(self) -> None:
        original = mod.SUMMARY
        with tempfile.TemporaryDirectory() as temp_dir:
            mod.SUMMARY = Path(temp_dir) / "missing-summary.md"
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn("summary_exists", failed_checks)
        mod.SUMMARY = original

    def test_missing_evidence_fails(self) -> None:
        original = mod.EVIDENCE
        with tempfile.TemporaryDirectory() as temp_dir:
            mod.EVIDENCE = Path(temp_dir) / "missing-evidence.json"
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn("evidence_exists", failed_checks)
        mod.EVIDENCE = original

    def test_missing_impl_fails(self) -> None:
        original = mod.IMPL
        with tempfile.TemporaryDirectory() as temp_dir:
            mod.IMPL = Path(temp_dir) / "missing-impl.rs"
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn("impl_exists", failed_checks)
        mod.IMPL = original


class TestConstants(unittest.TestCase):
    def test_event_code_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 6)

    def test_error_code_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_ERROR_CODES), 4)

    def test_invariant_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 3)

    def test_impl_symbols_minimum(self) -> None:
        self.assertGreaterEqual(len(mod.REQUIRED_IMPL_SYMBOLS), 15)

    def test_trust_decision_variant_count(self) -> None:
        self.assertEqual(len(mod.TRUST_DECISION_VARIANTS), 3)

    def test_proof_field_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_PROOF_FIELDS), 9)

    def test_predicate_field_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_PREDICATE_FIELDS), 7)


if __name__ == "__main__":
    unittest.main()
