"""Unit tests for check_evidence_ledger.py (bd-2e73)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_evidence_ledger.py"
IMPL = ROOT / "crates" / "franken-node" / "src" / "observability" / "evidence_ledger.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-2e73_contract.md"

sys.path.insert(0, str(ROOT / "scripts"))
import check_evidence_ledger as cel


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

    def test_evidence_ledger(self):
        self.assertIn("pub struct EvidenceLedger", self.content)

    def test_evidence_entry(self):
        self.assertIn("pub struct EvidenceEntry", self.content)

    def test_ledger_capacity(self):
        self.assertIn("pub struct LedgerCapacity", self.content)

    def test_shared_evidence_ledger(self):
        self.assertIn("pub struct SharedEvidenceLedger", self.content)

    def test_lab_spill_mode(self):
        self.assertIn("pub struct LabSpillMode", self.content)

    def test_decision_kind(self):
        self.assertIn("pub enum DecisionKind", self.content)


class TestEventCodes(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_all_event_codes(self):
        for code in ["EVD-LEDGER-001", "EVD-LEDGER-002", "EVD-LEDGER-003", "EVD-LEDGER-004"]:
            self.assertIn(code, self.content)


class TestMethodPresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_append(self):
        self.assertIn("fn append(", self.content)

    def test_iter_recent(self):
        self.assertIn("fn iter_recent(", self.content)

    def test_snapshot(self):
        self.assertIn("fn snapshot(", self.content)

    def test_evict_oldest(self):
        self.assertIn("fn evict_oldest(", self.content)


class TestSendSync(unittest.TestCase):
    def test_compile_time_assertion(self):
        content = IMPL.read_text()
        self.assertIn("assert_send_sync", content)


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test(self):
        ok, results = cel.self_test()
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
        self.assertEqual(payload["bead_id"], "bd-2e73")

    def test_cli_human(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("bd-2e73", completed.stdout)


class TestAllChecksPass(unittest.TestCase):
    def test_no_failures(self):
        result = cel.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0,
                         f"Failing: {json.dumps(failing, indent=2)}")


if __name__ == "__main__":
    unittest.main()
