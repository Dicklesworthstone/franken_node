"""Unit tests for scripts/check_section_10_18_gate.py (bd-2hjg)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_section_10_18_gate.py"

spec = importlib.util.spec_from_file_location("check_section_10_18_gate", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-2hjg")
        self.assertEqual(result["section"], "10.18")
        self.assertIn(result["verdict"], ("PASS", "FAIL"))
        self.assertEqual(result["failed"], result["total"] - result["passed"])
        self.assertEqual(result["total"], len(result["checks"]))
        self.assertTrue(result["gate"])

    def test_check_entries_shape(self) -> None:
        result = mod.run_all()
        for check in result["checks"]:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)
            self.assertIsInstance(check["check"], str)
            self.assertIsInstance(check["pass"], bool)
            self.assertIsInstance(check["detail"], str)

    def test_section_beads_count(self) -> None:
        result = mod.run_all()
        self.assertEqual(len(result["section_beads"]), 13)

    def test_has_timestamp(self) -> None:
        result = mod.run_all()
        self.assertIn("timestamp", result)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS", self._failures(result))

    def test_self_test_shape(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["mode"], "self-test")
        self.assertGreaterEqual(result["total"], 7)
        self.assertEqual(result["failed"], result["total"] - result["passed"])

    @staticmethod
    def _failures(result: dict) -> str:
        return "\n".join(f"FAIL: {c['check']}: {c['detail']}" for c in result["checks"] if not c["pass"])


class TestCli(unittest.TestCase):
    def test_self_test_cli_exit_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_self_test_json_cli(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-2hjg")
        self.assertEqual(parsed["mode"], "self-test")

    def test_json_output_parseable(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-2hjg")
        self.assertIn("checks", parsed)


class TestConstants(unittest.TestCase):
    def test_section_bead_count(self) -> None:
        self.assertEqual(len(mod.SECTION_BEADS), 13)

    def test_domain_group_count(self) -> None:
        self.assertEqual(len(mod.DOMAIN_GROUPS), 13)

    def test_all_beads_in_domain_groups(self) -> None:
        domain_beads = set()
        for bead_ids in mod.DOMAIN_GROUPS.values():
            domain_beads.update(bead_ids)
        section_bead_ids = {b[0] for b in mod.SECTION_BEADS}
        self.assertEqual(domain_beads, section_bead_ids)

    def test_gate_bead_id(self) -> None:
        self.assertEqual(mod.GATE_BEAD, "bd-2hjg")


class TestEvidencePass(unittest.TestCase):
    def test_verdict_pass(self) -> None:
        self.assertTrue(mod._evidence_pass({"verdict": "PASS"}))

    def test_verdict_fail(self) -> None:
        self.assertFalse(mod._evidence_pass({"verdict": "FAIL"}))

    def test_overall_pass_true(self) -> None:
        self.assertTrue(mod._evidence_pass({"overall_pass": True}))

    def test_status_completed(self) -> None:
        self.assertTrue(mod._evidence_pass({"status": "completed"}))

    def test_empty_dict_fails(self) -> None:
        self.assertFalse(mod._evidence_pass({}))


if __name__ == "__main__":
    unittest.main()
