"""Unit tests for scripts/check_vef_adversarial_suite.py (bd-3ptu)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_vef_adversarial_suite.py"

spec = importlib.util.spec_from_file_location("check_vef_adversarial_suite", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-3ptu")
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
        self.assertEqual(parsed["bead_id"], "bd-3ptu")
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
            mod.SUMMARY = Path(temp_dir) / "missing-summary.md"
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn("summary_mentions_bd", failed_checks)
        mod.SUMMARY = original

    def test_comment_only_suite_markers_fail_closed(self) -> None:
        original_primary = mod.SUITE_PRIMARY
        original_harness = mod.SUITE_HARNESS
        commented_tests = "\n".join(
            f"// #[test]\n// fn commented_test_{idx}() {{}}" for idx in range(12)
        )
        comment_only_suite = f"""
// receipt tampering proof replay stale-policy commitment mismatch
// tamper replay stale commitment
// expect_err matches!(result, Err(_))
// VEF-ADVERSARIAL-001
// VEF-ADVERSARIAL-002
// VEF-ADVERSARIAL-ERR-TAMPER
// VEF-ADVERSARIAL-ERR-REPLAY
// VEF-ADVERSARIAL-ERR-STALE-POLICY
// VEF-ADVERSARIAL-ERR-COMMITMENT
// 100 false positive legitimate
/*
receipt tampering
proof replay
stale-policy
commitment mismatch
VEF-ADVERSARIAL-001
VEF-ADVERSARIAL-ERR-TAMPER
*/
{commented_tests}
"""

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                suite_path = Path(temp_dir) / "vef_adversarial_suite.rs"
                suite_path.write_text(comment_only_suite, encoding="utf-8")
                mod.SUITE_PRIMARY = suite_path
                mod.SUITE_HARNESS = Path(temp_dir) / "missing_harness.rs"

                mod.RESULTS.clear()
                mod.check_suite_content()
                checks = {entry["check"]: entry["pass"] for entry in mod.RESULTS}

                self.assertTrue(checks["suite_readable"])
                expected_failures = [
                    "suite_symbol_tamper",
                    "suite_symbol_replay",
                    "suite_symbol_stale",
                    "suite_symbol_commitment",
                    "suite_symbol_error_assertion",
                    "suite_attack_class_receipt tampering",
                    "suite_attack_class_proof replay",
                    "suite_attack_class_stale-policy",
                    "suite_attack_class_commitment mismatch",
                    "suite_event_code_VEF-ADVERSARIAL-001",
                    "suite_event_code_VEF-ADVERSARIAL-002",
                    "suite_error_code_VEF-ADVERSARIAL-ERR-TAMPER",
                    "suite_error_code_VEF-ADVERSARIAL-ERR-REPLAY",
                    "suite_error_code_VEF-ADVERSARIAL-ERR-STALE-POLICY",
                    "suite_error_code_VEF-ADVERSARIAL-ERR-COMMITMENT",
                    "suite_minimum_test_count",
                    "suite_has_determinism_loop_hint",
                    "suite_mentions_false_positive_guard",
                ]
                for check_name in expected_failures:
                    self.assertIn(check_name, checks)
                    self.assertFalse(checks[check_name], check_name)
        finally:
            mod.SUITE_PRIMARY = original_primary
            mod.SUITE_HARNESS = original_harness


if __name__ == "__main__":
    unittest.main()
