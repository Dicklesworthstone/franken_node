"""Unit tests for check_hardening_state.py (bd-3rya)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_hardening_state.py"
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "hardening_state_machine.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-3rya_contract.md"

sys.path.insert(0, str(ROOT / "scripts"))
import check_hardening_state as chs


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

    def test_hardening_level(self):
        self.assertIn("pub enum HardeningLevel", self.content)

    def test_state_machine(self):
        self.assertIn("pub struct HardeningStateMachine", self.content)

    def test_governance_artifact(self):
        self.assertIn("pub struct GovernanceRollbackArtifact", self.content)

    def test_hardening_error(self):
        self.assertIn("pub enum HardeningError", self.content)


class TestLevelPresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_five_levels(self):
        for level in ["Baseline", "Standard", "Enhanced", "Maximum", "Critical"]:
            self.assertIn(level, self.content)


class TestMethodPresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_escalate(self):
        self.assertIn("fn escalate(", self.content)

    def test_governance_rollback(self):
        self.assertIn("fn governance_rollback(", self.content)

    def test_replay(self):
        self.assertIn("fn replay_transitions(", self.content)


class TestInvariants(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_all_invariants(self):
        for inv in ["INV-HARDEN-MONOTONIC", "INV-HARDEN-DURABLE",
                     "INV-HARDEN-AUDITABLE", "INV-HARDEN-GOVERNANCE"]:
            self.assertIn(inv, self.content)


class TestRequiredTests(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_escalation_tests(self):
        self.assertIn("escalate_full_chain", self.content)
        self.assertIn("escalate_baseline_to_standard", self.content)

    def test_regression_tests(self):
        self.assertIn("regression_same_level_rejected", self.content)
        self.assertIn("regression_lower_level_rejected", self.content)

    def test_rollback_tests(self):
        self.assertIn("governance_rollback_with_valid_artifact", self.content)
        self.assertIn("governance_rollback_missing_signature", self.content)

    def test_replay_tests(self):
        self.assertIn("replay_determinism", self.content)
        self.assertIn("replay_multi_transition", self.content)

    def test_lifecycle_test(self):
        self.assertIn("full_lifecycle_escalate_rollback_escalate", self.content)


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test(self):
        result = chs.self_test()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["summary"]["failing_checks"], 0)

    def test_cli_json(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["verdict"], "PASS")
        self.assertEqual(payload["bead"], "bd-3rya")

    def test_cli_human(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("bd-3rya", completed.stdout)


class TestAllChecksPass(unittest.TestCase):
    def test_no_failures(self):
        result = chs.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0,
                        f"Failing: {json.dumps(failing, indent=2)}")


if __name__ == "__main__":
    unittest.main()
