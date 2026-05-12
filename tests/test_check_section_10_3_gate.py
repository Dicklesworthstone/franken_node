"""Unit tests for scripts/check_section_10_3_gate.py (bd-3enl)."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_section_10_3_gate.py"
LEGACY_SCRIPT = ROOT / "scripts" / "gate_section_10_3.py"


def load_script_namespace(path: Path) -> SimpleNamespace:
    return SimpleNamespace(**runpy.run_path(str(path)))


mod = load_script_namespace(SCRIPT)
legacy_mod = load_script_namespace(LEGACY_SCRIPT)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-3enl")
        self.assertEqual(result["section"], "10.3")
        self.assertIn(result["verdict"], ("PASS", "FAIL"))
        self.assertEqual(result["failed"], result["total"] - result["passed"])
        self.assertEqual(result["total"], len(result["checks"]))
        self.assertTrue(result["gate"])
        self.assertEqual(result["completion_debt"]["completion_bead"], "bd-2avo.1")

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
        self.assertEqual(len(result["section_beads"]), 8)

    def test_has_timestamp(self) -> None:
        result = mod.run_all()
        self.assertIn("timestamp", result)

    def test_completion_debt_obligations_present(self) -> None:
        result = mod.run_all()
        obligations = {
            item["spec_item"]: item
            for item in result["completion_debt"]["coverage_obligations"]
        }
        self.assertEqual(
            set(obligations),
            {"tests.unit.primary", "tests.e2e.primary", "migrations.primary", "telemetry.primary"},
        )
        self.assertEqual(obligations["migrations.primary"]["status"], "covered")
        self.assertIn("tests/e2e/migration_cohort_validation.sh", obligations["tests.e2e.primary"]["evidence_paths"])

    def test_completion_debt_check_fails_when_spec_item_missing(self) -> None:
        globals_dict = mod.check_completion_debt_coverage.__globals__
        original = globals_dict["COMPLETION_DEBT_OBLIGATIONS"]
        globals_dict["COMPLETION_DEBT_OBLIGATIONS"] = [
            item
            for item in original
            if item["spec_item"] != "telemetry.primary"
        ]
        try:
            mod.RESULTS.clear()
            check = mod.check_completion_debt_coverage()
            self.assertFalse(check["pass"])
            self.assertIn("telemetry.primary", check["detail"])
        finally:
            globals_dict["COMPLETION_DEBT_OBLIGATIONS"] = original

    def test_completion_debt_check_fails_when_evidence_path_missing(self) -> None:
        globals_dict = mod.check_completion_debt_coverage.__globals__
        original = globals_dict["COMPLETION_DEBT_OBLIGATIONS"]
        mutated = [dict(item) for item in original]
        mutated[0] = dict(mutated[0])
        mutated[0]["evidence_paths"] = list(mutated[0]["evidence_paths"]) + ["tests/no_such_completion_debt_test.py"]
        globals_dict["COMPLETION_DEBT_OBLIGATIONS"] = mutated
        try:
            mod.RESULTS.clear()
            check = mod.check_completion_debt_coverage()
            self.assertFalse(check["pass"])
            self.assertIn("tests/no_such_completion_debt_test.py", check["detail"])
        finally:
            globals_dict["COMPLETION_DEBT_OBLIGATIONS"] = original


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
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-3enl")
        self.assertEqual(parsed["mode"], "self-test")

    def test_json_output_parseable(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-3enl")
        self.assertIn("checks", parsed)


class TestLegacySectionGate(unittest.TestCase):
    def test_legacy_run_script_missing_file_fails_closed(self) -> None:
        result = legacy_mod.run_script("scripts/not_a_real_section_gate.py")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("Not found", result["error"])

    def test_legacy_evidence_checks_all_section_beads(self) -> None:
        result = legacy_mod.check_evidence()
        self.assertEqual(set(result["details"]), set(legacy_mod.EVIDENCE_DIRS))
        self.assertIn(result["status"], ("PASS", "FAIL"))

    def test_legacy_json_cli_output_parseable(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(LEGACY_SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["gate"], "section_10_3_verification")
        self.assertEqual(parsed["section"], "10.3")
        self.assertIn(parsed["verdict"], ("PASS", "FAIL"))


class TestConstants(unittest.TestCase):
    def test_section_bead_count(self) -> None:
        self.assertEqual(len(mod.SECTION_BEADS), 8)

    def test_domain_group_count(self) -> None:
        self.assertEqual(len(mod.DOMAIN_GROUPS), 8)

    def test_all_beads_in_domain_groups(self) -> None:
        domain_beads = set()
        for bead_ids in mod.DOMAIN_GROUPS.values():
            domain_beads.update(bead_ids)
        section_bead_ids = {b[0] for b in mod.SECTION_BEADS}
        self.assertEqual(domain_beads, section_bead_ids)

    def test_gate_bead_id(self) -> None:
        self.assertEqual(mod.GATE_BEAD, "bd-3enl")

    def test_completion_debt_required_items(self) -> None:
        self.assertEqual(
            mod.COMPLETION_DEBT_REQUIRED_SPEC_ITEMS,
            {"tests.unit.primary", "tests.e2e.primary", "migrations.primary", "telemetry.primary"},
        )


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

    def test_verification_results_check_script(self) -> None:
        data = {
            "verification_results": {
                "check_script": {"verdict": "PASS"},
                "unit_tests": {"verdict": "PASS"},
            }
        }
        self.assertTrue(mod._evidence_pass(data))

    def test_verification_results_mixed_fail(self) -> None:
        data = {
            "verification_results": {
                "check_script": {"verdict": "PASS"},
                "unit_tests": {"verdict": "FAIL"},
            }
        }
        self.assertFalse(mod._evidence_pass(data))


if __name__ == "__main__":
    unittest.main()
