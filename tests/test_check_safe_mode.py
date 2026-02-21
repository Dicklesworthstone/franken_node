"""Unit tests for check_safe_mode.py verification script (bd-k6o)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_safe_mode as checker


class TestFileExistence(unittest.TestCase):
    def test_impl_exists(self):
        result = checker.run_all()
        impl_check = next(c for c in result["checks"] if c["name"] == "impl_exists")
        self.assertTrue(impl_check["passed"], impl_check["detail"])

    def test_spec_exists(self):
        result = checker.run_all()
        spec_check = next(c for c in result["checks"] if c["name"] == "spec_exists")
        self.assertTrue(spec_check["passed"], spec_check["detail"])

    def test_policy_exists(self):
        result = checker.run_all()
        policy_check = next(c for c in result["checks"] if c["name"] == "policy_exists")
        self.assertTrue(policy_check["passed"], policy_check["detail"])

    def test_module_registered(self):
        result = checker.run_all()
        mod_check = next(c for c in result["checks"] if c["name"] == "module_registered")
        self.assertTrue(mod_check["passed"], mod_check["detail"])


class TestEventCodes(unittest.TestCase):
    def test_event_codes_in_impl(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"event_code_impl:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_event_codes_in_spec(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"event_code_spec:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_event_code_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 4)


class TestInvariants(unittest.TestCase):
    def test_invariants_in_impl(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"invariant_impl:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_invariants_in_spec(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"invariant_spec:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_invariant_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)


class TestTypes(unittest.TestCase):
    def test_all_types_present(self):
        result = checker.run_all()
        for ty in checker.REQUIRED_TYPES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"type:{ty}")
            self.assertTrue(check["passed"], f"{ty}: {check['detail']}")

    def test_type_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TYPES), 10)


class TestMethods(unittest.TestCase):
    def test_all_methods_present(self):
        result = checker.run_all()
        for method in checker.REQUIRED_METHODS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"method:{method}")
            self.assertTrue(check["passed"], f"{method}: {check['detail']}")

    def test_method_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_METHODS), 25)


class TestEntryReasonVariants(unittest.TestCase):
    def test_all_variants_present(self):
        result = checker.run_all()
        for v in checker.ENTRY_REASON_VARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"entry_reason:{v}")
            self.assertTrue(check["passed"], f"{v}: {check['detail']}")

    def test_variant_count(self):
        self.assertEqual(len(checker.ENTRY_REASON_VARIANTS), 6)


class TestCapabilityVariants(unittest.TestCase):
    def test_all_variants_present(self):
        result = checker.run_all()
        for v in checker.CAPABILITY_VARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"capability:{v}")
            self.assertTrue(check["passed"], f"{v}: {check['detail']}")

    def test_variant_count(self):
        self.assertEqual(len(checker.CAPABILITY_VARIANTS), 6)


class TestOperationFlags(unittest.TestCase):
    def test_all_flags_in_spec(self):
        result = checker.run_all()
        for flag in checker.OPERATION_FLAGS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"flag_spec:{flag}")
            self.assertTrue(check["passed"], f"{flag}: {check['detail']}")


class TestSerdeDerive(unittest.TestCase):
    def test_serde(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "serde_derives")
        self.assertTrue(check["passed"])


class TestImplTests(unittest.TestCase):
    def test_all_tests_present(self):
        result = checker.run_all()
        for test in checker.REQUIRED_TESTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"test:{test}")
            self.assertTrue(check["passed"], f"{test}: {check['detail']}")

    def test_required_test_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TESTS), 80)


class TestTestCount(unittest.TestCase):
    def test_minimum_80(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "test_count")
        self.assertTrue(check["passed"], check["detail"])


class TestDeterminismContract(unittest.TestCase):
    def test_determinism_documented(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "determinism_contract")
        self.assertTrue(check["passed"], check["detail"])


class TestExitProtocol(unittest.TestCase):
    def test_exit_protocol_documented(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "exit_protocol")
        self.assertTrue(check["passed"], check["detail"])


class TestTrustReverification(unittest.TestCase):
    def test_trust_reverification_documented(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "trust_reverification")
        self.assertTrue(check["passed"], check["detail"])


class TestPolicyGovernance(unittest.TestCase):
    def test_governance_documented(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "policy_governance")
        self.assertTrue(check["passed"], check["detail"])


class TestDrillTests(unittest.TestCase):
    def test_drill_tests_present(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "drill_tests")
        self.assertTrue(check["passed"], check["detail"])


class TestRunAll(unittest.TestCase):
    def test_structure(self):
        result = checker.run_all()
        self.assertIn("bead_id", result)
        self.assertIn("section", result)
        self.assertIn("checks", result)
        self.assertIn("verdict", result)
        self.assertIn("passed", result)
        self.assertIn("failed", result)
        self.assertIn("total", result)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-k6o")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.8")

    def test_check_count_reasonable(self):
        result = checker.run_all()
        # Should have many checks given all the content validation
        self.assertGreaterEqual(result["total"], 100)

    def test_all_checks_have_required_keys(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_pass_values_are_bool(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIsInstance(check["passed"], bool)


class TestSelfTest(unittest.TestCase):
    def test_self_test_runs(self):
        # Should not raise
        checker.self_test()


class TestSafeRel(unittest.TestCase):
    def test_path_within_root(self):
        rel = checker._safe_rel(checker.IMPL)
        self.assertNotIn(str(checker.ROOT), rel)
        self.assertIn("safe_mode.rs", rel)

    def test_path_outside_root(self):
        outside = Path("/tmp/something/else.txt")
        rel = checker._safe_rel(outside)
        self.assertEqual(rel, str(outside))


class TestConstants(unittest.TestCase):
    def test_event_codes(self):
        self.assertEqual(checker.EVENT_CODES, ["SMO-001", "SMO-002", "SMO-003", "SMO-004"])

    def test_invariants(self):
        self.assertEqual(len(checker.INVARIANTS), 4)
        self.assertIn("INV-SMO-DETERMINISTIC", checker.INVARIANTS)
        self.assertIn("INV-SMO-RECOVERY", checker.INVARIANTS)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_all()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_safe_mode.py"), "--json"],
            capture_output=True, text=True,
        )
        # May not be PASS yet if evidence/summary not written, but should be valid JSON
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-k6o")
        self.assertIn("checks", data)

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_safe_mode.py"), "--self-test"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("self_test passed", proc.stdout)


class TestAllChecksPass(unittest.TestCase):
    """Final integration test: run after evidence and summary are written."""

    def test_all_pass_except_evidence(self):
        """All checks should pass except possibly evidence/summary."""
        result = checker.run_all()
        # Filter out evidence/summary checks which need the full run
        non_evidence = [c for c in result["checks"]
                        if c["name"] not in ("verification_evidence",
                                             "verification_summary")]
        failing = [c for c in non_evidence if not c["passed"]]
        self.assertEqual(
            len(failing), 0,
            f"Failing checks: {json.dumps(failing, indent=2)}",
        )


if __name__ == "__main__":
    unittest.main()
