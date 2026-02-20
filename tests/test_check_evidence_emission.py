"""Unit tests for check_evidence_emission.py (bd-oolt)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_evidence_emission.py"
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "evidence_emission.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-oolt_contract.md"

sys.path.insert(0, str(ROOT / "scripts"))
import check_evidence_emission as cee


class TestFileExistence(unittest.TestCase):
    def test_implementation_exists(self):
        self.assertTrue(IMPL.is_file())

    def test_spec_exists(self):
        self.assertTrue(SPEC.is_file())

    def test_script_exists(self):
        self.assertTrue(SCRIPT.is_file())


class TestTypePresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_policy_action(self):
        self.assertIn("pub enum PolicyAction", self.content)

    def test_action_id(self):
        self.assertIn("pub struct ActionId", self.content)

    def test_evidence_requirement(self):
        self.assertIn("pub struct EvidenceRequirement", self.content)

    def test_conformance_checker(self):
        self.assertIn("pub struct EvidenceConformanceChecker", self.content)

    def test_conformance_error(self):
        self.assertIn("pub enum ConformanceError", self.content)

    def test_policy_action_outcome(self):
        self.assertIn("pub enum PolicyActionOutcome", self.content)


class TestEventCodes(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_all_event_codes(self):
        for code in ["EVD-POLICY-001", "EVD-POLICY-002", "EVD-POLICY-003"]:
            self.assertIn(code, self.content)


class TestActionVariants(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_commit(self):
        self.assertIn("Commit", self.content)

    def test_abort(self):
        self.assertIn("Abort", self.content)

    def test_quarantine(self):
        self.assertIn("Quarantine", self.content)

    def test_release(self):
        self.assertIn("Release", self.content)


class TestErrorCodes(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_missing_evidence(self):
        self.assertIn("ERR_MISSING_EVIDENCE", self.content)

    def test_kind_mismatch(self):
        self.assertIn("ERR_DECISION_KIND_MISMATCH", self.content)

    def test_id_mismatch(self):
        self.assertIn("ERR_ACTION_ID_MISMATCH", self.content)


class TestMethodPresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_verify_and_execute(self):
        self.assertIn("fn verify_and_execute(", self.content)

    def test_coverage_check(self):
        self.assertIn("fn coverage_check(", self.content)

    def test_build_evidence_entry(self):
        self.assertIn("fn build_evidence_entry(", self.content)


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test(self):
        ok, results = cee.self_test()
        self.assertTrue(ok)

    def test_cli_json(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["verdict"], "PASS")
        self.assertEqual(payload["bead_id"], "bd-oolt")

    def test_cli_human(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("bd-oolt", completed.stdout)


class TestAllChecksPass(unittest.TestCase):
    def test_no_failures(self):
        result = cee.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0,
                         f"Failing: {json.dumps(failing, indent=2)}")


if __name__ == "__main__":
    unittest.main()
