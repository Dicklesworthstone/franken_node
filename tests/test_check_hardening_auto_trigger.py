"""Unit tests for check_hardening_auto_trigger.py (bd-1zym)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_hardening_auto_trigger.py"
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "hardening_auto_trigger.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-1zym_contract.md"

sys.path.insert(0, str(ROOT / "scripts"))
import check_hardening_auto_trigger as chat


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

    def test_trigger_result(self):
        self.assertIn("pub enum TriggerResult", self.content)

    def test_trigger_event(self):
        self.assertIn("pub struct TriggerEvent", self.content)

    def test_trigger_config(self):
        self.assertIn("pub struct TriggerConfig", self.content)

    def test_hardening_auto_trigger(self):
        self.assertIn("pub struct HardeningAutoTrigger", self.content)


class TestEventCodes(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_all_event_codes(self):
        for code in ["EVD-AUTOTRIG-001", "EVD-AUTOTRIG-002",
                      "EVD-AUTOTRIG-003", "EVD-AUTOTRIG-004"]:
            self.assertIn(code, self.content)


class TestInvariants(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_latency_invariant(self):
        self.assertIn("INV-AUTOTRIG-LATENCY", self.content)

    def test_idempotent_invariant(self):
        self.assertIn("INV-AUTOTRIG-IDEMPOTENT", self.content)

    def test_causal_invariant(self):
        self.assertIn("INV-AUTOTRIG-CAUSAL", self.content)


class TestMethodPresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_on_guardrail_rejection(self):
        self.assertIn("fn on_guardrail_rejection(", self.content)

    def test_reset_idempotency(self):
        self.assertIn("fn reset_idempotency(", self.content)

    def test_events(self):
        self.assertIn("fn events(", self.content)

    def test_to_jsonl(self):
        self.assertIn("fn to_jsonl(", self.content)


class TestUpstreamIntegration(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_imports_state_machine(self):
        self.assertIn("HardeningStateMachine", self.content)

    def test_imports_guardrail_rejection(self):
        self.assertIn("GuardrailRejection", self.content)

    def test_imports_hardening_level(self):
        self.assertIn("HardeningLevel", self.content)


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test(self):
        ok, results = chat.self_test()
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
        self.assertEqual(payload["bead_id"], "bd-1zym")

    def test_cli_human(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("bd-1zym", completed.stdout)


class TestAllChecksPass(unittest.TestCase):
    def test_no_failures(self):
        result = chat.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0,
                         f"Failing: {json.dumps(failing, indent=2)}")


if __name__ == "__main__":
    unittest.main()
