"""Unit tests for scripts/check_vef_policy_constraints.py (bd-16fq)."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_vef_policy_constraints.py"


class ScriptNamespace:
    def __init__(self, script_globals: dict[str, object]) -> None:
        object.__setattr__(self, "_script_globals", script_globals)

    def __getattr__(self, name: str) -> object:
        return self._script_globals[name]

    def __setattr__(self, name: str, value: object) -> None:
        self._script_globals[name] = value


script_globals = runpy.run_path(str(SCRIPT))
mod = ScriptNamespace(script_globals["run_all"].__globals__)


def load_json(text: str) -> dict[str, object]:
    return json.JSONDecoder().decode(text)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_returns_expected_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-16fq")
        self.assertEqual(result["section"], "10.18")
        self.assertIn(result["verdict"], ("PASS", "FAIL"))
        self.assertEqual(result["failed"], result["total"] - result["passed"])
        self.assertIsInstance(result["checks"], list)
        self.assertEqual(result["total"], len(result["checks"]))

    def test_check_entries_have_required_keys(self) -> None:
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
        return "\n".join(f"FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


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
        parsed = load_json(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-16fq")
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
    def test_missing_summary_file_trips_failure(self) -> None:
        original = mod.SUMMARY
        with tempfile.TemporaryDirectory() as tmp:
            mod.SUMMARY = Path(tmp) / "missing-summary.md"
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn("summary_exists", failed_checks)
        mod.SUMMARY = original


if __name__ == "__main__":
    unittest.main()
