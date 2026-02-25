#!/usr/bin/env python3
"""Unit tests for check_section_10_7_gate.py (bd-1rwq)."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Load the gate module
_spec = importlib.util.spec_from_file_location(
    "check_gate", ROOT / "scripts" / "check_section_10_7_gate.py"
)
mod = importlib.util.module_from_spec(_spec)
sys.modules["check_gate"] = mod
_spec.loader.exec_module(mod)


class TestSelfTest(unittest.TestCase):
    """Verify self_test returns correct structure and PASS verdict."""

    def test_verdict_pass(self):
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_bead_id(self):
        result = mod.self_test()
        self.assertEqual(result["bead"], "bd-1rwq")

    def test_section(self):
        result = mod.self_test()
        self.assertEqual(result["section"], "10.7")

    def test_name(self):
        result = mod.self_test()
        self.assertEqual(result["name"], "section_10_7_verification_gate")

    def test_no_failures(self):
        result = mod.self_test()
        self.assertEqual(result["failed"], 0)

    def test_events_present(self):
        result = mod.self_test()
        self.assertIn("GATE_10_7_EVALUATION_STARTED", result["events"])
        self.assertIn("GATE_10_7_VERDICT_EMITTED", result["events"])

    def test_summary_beads(self):
        result = mod.self_test()
        self.assertEqual(result["summary"]["total_beads"], 6)
        self.assertEqual(result["summary"]["beads_passing"], 6)


class TestAllChecksPass(unittest.TestCase):
    """Verify all individual checks pass."""

    def test_all_pass(self):
        checks = mod._checks()
        failing = [c for c in checks if not c["passed"]]
        self.assertEqual(len(failing), 0, f"Failing checks: {failing}")

    def test_minimum_check_count(self):
        checks = mod._checks()
        self.assertGreaterEqual(len(checks), 28)


class TestCheckStructure(unittest.TestCase):
    """Verify each check has the correct structure."""

    def test_check_keys(self):
        checks = mod._checks()
        for c in checks:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)

    def test_check_types(self):
        checks = mod._checks()
        for c in checks:
            self.assertIsInstance(c["check"], str)
            self.assertIsInstance(c["passed"], bool)
            self.assertIsInstance(c["detail"], str)


class TestBeadEvidenceChecks(unittest.TestCase):
    """Verify bead evidence checks cover all 6 beads."""

    def test_evidence_checks_exist(self):
        checks = mod._checks()
        check_names = {c["check"] for c in checks}
        for bead_id in ["bd-2ja", "bd-s6y", "bd-1ul", "bd-1u4", "bd-3ex", "bd-2pu"]:
            self.assertIn(f"evidence_exists:{bead_id}", check_names)
            self.assertIn(f"verdict_pass:{bead_id}", check_names)
            self.assertIn(f"gate_script_exists:{bead_id}", check_names)


class TestCoverageChecks(unittest.TestCase):
    """Verify domain-specific coverage checks."""

    def test_corpus_band_coverage(self):
        checks = mod._checks()
        corpus_check = next(c for c in checks if c["check"] == "corpus_band_coverage")
        self.assertTrue(corpus_check["passed"])

    def test_fuzz_corpus_exists(self):
        checks = mod._checks()
        migration = next(c for c in checks if c["check"] == "fuzz_corpus_migration_exists")
        shim = next(c for c in checks if c["check"] == "fuzz_corpus_shim_exists")
        self.assertTrue(migration["passed"])
        self.assertTrue(shim["passed"])


class TestMissingEvidence(unittest.TestCase):
    """Verify detection of missing evidence."""

    def test_missing_evidence_causes_fail(self):
        fake_path = Path("/nonexistent/path/evidence.json")
        original = mod.SECTION_BEADS[0]["evidence"]
        try:
            mod.SECTION_BEADS[0]["evidence"] = fake_path
            checks = mod._checks()
            evidence_check = next(
                c for c in checks if c["check"] == "evidence_exists:bd-2ja"
            )
            self.assertFalse(evidence_check["passed"])
        finally:
            mod.SECTION_BEADS[0]["evidence"] = original


class TestJsonOutput(unittest.TestCase):
    """Verify CLI --json produces valid JSON with PASS verdict."""

    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_section_10_7_gate.py"), "--json"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["verdict"], "PASS")
        self.assertIn("checks", data)
        self.assertIn("events", data)


class TestSelfTestCli(unittest.TestCase):
    """Verify CLI --self-test exits 0."""

    def test_self_test_exits_zero(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_section_10_7_gate.py"), "--self-test"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
