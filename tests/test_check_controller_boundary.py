"""Unit tests for check_controller_boundary.py (bd-bq4p)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_controller_boundary.py"
IMPL = ROOT / "crates" / "franken-node" / "src" / "policy" / "controller_boundary_checks.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-bq4p_contract.md"
ENVELOPE = ROOT / "crates" / "franken-node" / "src" / "policy" / "correctness_envelope.rs"

sys.path.insert(0, str(ROOT / "scripts"))
import check_controller_boundary as ccb


class TestFileExistence(unittest.TestCase):
    def test_implementation_exists(self):
        self.assertTrue(IMPL.is_file())

    def test_spec_exists(self):
        self.assertTrue(SPEC.is_file())

    def test_script_exists(self):
        self.assertTrue(SCRIPT.is_file())

    def test_upstream_envelope_exists(self):
        self.assertTrue(ENVELOPE.is_file())


class TestTypePresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_error_class(self):
        self.assertIn("pub enum ErrorClass", self.content)

    def test_boundary_violation(self):
        self.assertIn("pub struct BoundaryViolation", self.content)

    def test_rejected_mutation_record(self):
        self.assertIn("pub struct RejectedMutationRecord", self.content)

    def test_controller_boundary_checker(self):
        self.assertIn("pub struct ControllerBoundaryChecker", self.content)


class TestErrorClassVariants(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_three_variants(self):
        for variant in ["CorrectnessSemanticMutation", "EnvelopeBypass", "UnknownInvariantTarget"]:
            self.assertIn(variant, self.content)


class TestMethodPresence(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_check_proposal(self):
        self.assertIn("fn check_proposal(", self.content)

    def test_rejected_mutations(self):
        self.assertIn("fn rejected_mutations(", self.content)

    def test_rejection_count(self):
        self.assertIn("fn rejection_count(", self.content)

    def test_rejection_report(self):
        self.assertIn("fn rejection_report(", self.content)

    def test_record_rejection(self):
        self.assertIn("fn record_rejection(", self.content)

    def test_serialize_audit_trail(self):
        self.assertIn("fn serialize_audit_trail(", self.content)

    def test_restore_audit_trail(self):
        self.assertIn("fn restore_audit_trail(", self.content)


class TestEventCodes(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_all_event_codes(self):
        for code in ["EVD-BOUNDARY-001", "EVD-BOUNDARY-002",
                      "EVD-BOUNDARY-003", "EVD-BOUNDARY-004"]:
            self.assertIn(code, self.content)


class TestInvariantMarkers(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_all_invariants(self):
        for inv in ["INV-BOUNDARY-MANDATORY", "INV-BOUNDARY-AUDITABLE",
                     "INV-BOUNDARY-STABLE-ERRORS", "INV-BOUNDARY-FAIL-CLOSED"]:
            self.assertIn(inv, self.content)


class TestUpstreamDependency(unittest.TestCase):
    def setUp(self):
        self.content = IMPL.read_text()

    def test_imports_correctness_envelope(self):
        self.assertIn("correctness_envelope", self.content)

    def test_uses_correctness_envelope_type(self):
        self.assertIn("CorrectnessEnvelope", self.content)

    def test_uses_is_within_envelope(self):
        self.assertIn("is_within_envelope", self.content)


class TestInvariantRejectionTests(unittest.TestCase):
    """Verify the impl has tests for each of the 12 canonical invariants."""

    def setUp(self):
        self.content = IMPL.read_text()

    def test_all_12_invariant_rejection_tests(self):
        tests = [
            "rejects_hardening_direction_mutation",
            "rejects_evidence_suppression",
            "rejects_seed_algorithm_change",
            "rejects_integrity_bypass",
            "rejects_ring_buffer_overflow_change",
            "rejects_epoch_decrement",
            "rejects_witness_hash_change",
            "rejects_guardrail_precedence_override",
            "rejects_object_class_mutation",
            "rejects_network_bypass",
            "rejects_marker_stream_rewrite",
            "rejects_receipt_chain_truncation",
        ]
        for t in tests:
            self.assertIn(t, self.content, f"Missing test: {t}")


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test(self):
        result = ccb.self_test()
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
        self.assertEqual(payload["bead"], "bd-bq4p")

    def test_cli_human(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=30,
            cwd=str(ROOT), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("bd-bq4p", completed.stdout)


class TestAllChecksPass(unittest.TestCase):
    def test_no_failures(self):
        result = ccb.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0,
                         f"Failing: {json.dumps(failing, indent=2)}")


if __name__ == "__main__":
    unittest.main()
