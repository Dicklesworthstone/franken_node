#!/usr/bin/env python3
"""Unit tests for check_split_contract.py."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_split_contract.py"


class TestSplitContractChecks(unittest.TestCase):
    """Test split contract enforcement checks."""

    def test_script_runs_successfully(self):
        """Script should run and produce JSON output."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, f"Script failed: {result.stderr}")
        output = json.loads(result.stdout)
        self.assertIn("verdict", output)
        self.assertIn("checks", output)

    def test_verdict_is_pass(self):
        """Current repo should pass all split contract checks."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        output = json.loads(result.stdout)
        self.assertEqual(output["verdict"], "PASS")

    def test_all_checks_present(self):
        """All expected check IDs should be in output."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        output = json.loads(result.stdout)
        check_ids = {c["id"] for c in output["checks"]}
        expected = {"SPLIT-NO-LOCAL", "SPLIT-PATH-DEPS", "SPLIT-NO-INTERNALS", "SPLIT-GOVERNANCE"}
        self.assertEqual(check_ids, expected)

    def test_no_local_engine_crates_check(self):
        """SPLIT-NO-LOCAL check should pass (no local engine dirs)."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        output = json.loads(result.stdout)
        check = next(c for c in output["checks"] if c["id"] == "SPLIT-NO-LOCAL")
        self.assertEqual(check["status"], "PASS")
        self.assertIn("checked", check["details"])

    def test_path_deps_check(self):
        """SPLIT-PATH-DEPS check should find valid engine path deps."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        output = json.loads(result.stdout)
        check = next(c for c in output["checks"] if c["id"] == "SPLIT-PATH-DEPS")
        self.assertEqual(check["status"], "PASS")
        # Should have found at least one cargo file with engine deps
        self.assertTrue(len(check["details"]["cargo_files"]) > 0)

    def test_governance_docs_check(self):
        """SPLIT-GOVERNANCE check should pass (required docs exist)."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        output = json.loads(result.stdout)
        check = next(c for c in output["checks"] if c["id"] == "SPLIT-GOVERNANCE")
        self.assertEqual(check["status"], "PASS")

    def test_summary_counts(self):
        """Summary should have correct pass/total counts."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
        )
        output = json.loads(result.stdout)
        summary = output["summary"]
        self.assertEqual(summary["total_checks"], 4)
        self.assertEqual(summary["passing_checks"], 4)
        self.assertEqual(summary["failing_checks"], 0)

    def test_human_readable_output(self):
        """Script should produce human-readable output without --json."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Split Contract", result.stdout)
        self.assertIn("Verdict: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
