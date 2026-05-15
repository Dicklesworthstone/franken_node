"""Unit tests for scripts/check_vef_proof_verifier.py (bd-1o4v)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_vef_proof_verifier.py"

spec = importlib.util.spec_from_file_location("check_vef_proof_verifier", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-1o4v")
        self.assertEqual(result["section"], "10.18")
        self.assertIn(result["verdict"], ("PASS", "FAIL"))
        self.assertEqual(result["failed"], result["total"] - result["passed"])
        self.assertEqual(result["total"], len(result["checks"]))

    def test_check_entries_shape(self) -> None:
        result = mod.run_all()
        for check in result["checks"]:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)
            self.assertIsInstance(check["check"], str)
            self.assertIsInstance(check["pass"], bool)
            self.assertIsInstance(check["detail"], str)

    def test_has_timestamp(self) -> None:
        result = mod.run_all()
        self.assertIn("timestamp", result)

    def test_total_checks_count(self) -> None:
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 50)


class TestVerdict(unittest.TestCase):
    def test_all_impl_checks_pass(self) -> None:
        result = mod.run_all()
        impl_checks = [c for c in result["checks"] if c["check"].startswith("impl_")]
        for c in impl_checks:
            self.assertTrue(c["pass"], f"FAIL: {c['check']}: {c['detail']}")


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS", self._failures(result))

    def test_self_test_shape(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["mode"], "self-test")
        self.assertGreaterEqual(result["total"], 9)
        self.assertEqual(result["failed"], result["total"] - result["passed"])

    @staticmethod
    def _failures(result: dict) -> str:
        return "\n".join(f"FAIL: {c['check']}: {c['detail']}" for c in result["checks"] if not c["pass"])


class TestCli(unittest.TestCase):
    def test_self_test_cli_exit_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_self_test_json_cli(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-1o4v")
        self.assertEqual(parsed["mode"], "self-test")

    def test_json_output_parseable(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-1o4v")
        self.assertIn("checks", parsed)


class TestCommentOnlyRegressions(unittest.TestCase):
    def test_comment_only_impl_markers_fail_closed(self) -> None:
        comment_only_impl = "\n".join(
            [
                "// pub enum TrustDecision { Allow, Deny(String), Degrade(u8) }",
                "// pub struct PolicyPredicate { pub action_class: String }",
                "// pub struct ComplianceProof { pub trace_id: String }",
                "// pub struct VerificationRequest { pub trace_id: String }",
                "// pub struct PredicateEvidence { pub reason: String }",
                "// pub struct VerificationReport { pub report_digest: String, pub trace_id: String }",
                "// pub struct VerifierEvent { pub trace_id: String }",
                "// pub struct VerifierError { pub code: String }",
                "// pub struct VerificationGateConfig { pub max_proof_age_millis: u64, pub degrade_threshold: u8, pub enforce_policy_version: bool }",
                "// pub struct ProofVerifier {}",
                "// pub struct VerificationGate {}",
                "// pub struct DecisionSummary { pub allow_count: usize }",
                "// pub fn validate_proof(",
                "// pub fn register_predicate(",
                "// pub fn remove_predicate(",
                "// pub fn verify(",
                "// pub fn verify_batch(",
                "// pub fn decision_summary(",
                "// pub fn events(",
                "// pub fn reports(",
                "// pub fn predicates(",
                '// pub const PROOF_VERIFIER_SCHEMA_VERSION: &str = "vef-proof-verifier-v1";',
                '// pub const INV_PVF_DETERMINISTIC: &str = "INV-PVF-DETERMINISTIC";',
                '// pub const INV_PVF_DENY_LOGGED: &str = "INV-PVF-DENY-LOGGED";',
                '// pub const INV_PVF_EVIDENCE_COMPLETE: &str = "INV-PVF-EVIDENCE-COMPLETE";',
                '// pub const PVF_001_REQUEST_RECEIVED: &str = "PVF-001";',
                '// pub const PVF_002_PROOF_VALIDATED: &str = "PVF-002";',
                '// pub const PVF_003_DECISION_EMITTED: &str = "PVF-003";',
                '// pub const PVF_004_DENY_LOGGED: &str = "PVF-004";',
                '// pub const PVF_005_DEGRADE_LOGGED: &str = "PVF-005";',
                '// pub const PVF_006_REPORT_FINALIZED: &str = "PVF-006";',
                '// pub const ERR_PVF_PROOF_EXPIRED: &str = "ERR-PVF-PROOF-EXPIRED";',
                '// pub const ERR_PVF_POLICY_MISSING: &str = "ERR-PVF-POLICY-MISSING";',
                '// pub const ERR_PVF_INVALID_FORMAT: &str = "ERR-PVF-INVALID-FORMAT";',
                '// pub const ERR_PVF_INTERNAL: &str = "ERR-PVF-INTERNAL";',
                "// BTreeMap Sha256 Serialize Deserialize trace_id report_digest compute_report_digest",
                "// expiry freshness action_class confidence witness policy_version expired",
            ]
            + ["// #[test]\n// fn comment_only_test_marker() {}" for _ in range(20)]
        )

        def fake_read(path: Path) -> str:
            if path == mod.IMPL_FILE:
                return comment_only_impl
            return ""

        mod.RESULTS.clear()
        with patch.object(mod, "_read", side_effect=fake_read):
            mod.check_impl_symbols()
            mod.check_trust_decisions()
            mod.check_event_codes()
            mod.check_error_codes()
            mod.check_config_fields()
            mod.check_contract_properties()
            mod.check_unit_tests()

        checks = {check["check"]: check for check in mod.RESULTS}
        self.assertFalse(checks["impl_symbol_TrustDecision"]["pass"])
        self.assertFalse(checks["decision_Allow"]["pass"])
        self.assertFalse(checks["event_PVF-001"]["pass"])
        self.assertFalse(checks["error_ERR-PVF-PROOF-EXPIRED"]["pass"])
        self.assertFalse(checks["config_max_proof_age_millis"]["pass"])
        self.assertFalse(checks["contract_deterministic"]["pass"])
        self.assertFalse(checks["contract_decision_summary"]["pass"])
        self.assertFalse(checks["impl_minimum_unit_tests"]["pass"])

    def test_comment_only_mod_wiring_fails_closed(self) -> None:
        original_read = mod._read

        def fake_read(path: Path) -> str:
            if path == mod.MOD_FILE:
                return "// pub mod proof_verifier;"
            return original_read(path)

        mod.RESULTS.clear()
        with patch.object(mod, "_read", side_effect=fake_read):
            mod.check_mod_wiring()

        checks = {check["check"]: check for check in mod.RESULTS}
        self.assertFalse(checks["mod_wires_proof_verifier"]["pass"])


class TestConstants(unittest.TestCase):
    def test_bead_id(self) -> None:
        self.assertEqual(mod.BEAD_ID, "bd-1o4v")

    def test_section(self) -> None:
        self.assertEqual(mod.SECTION, "10.18")

    def test_symbol_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_SYMBOLS), 21)

    def test_event_code_count(self) -> None:
        self.assertEqual(len(mod.EVENT_CODES), 6)

    def test_error_code_count(self) -> None:
        self.assertEqual(len(mod.ERROR_CODES), 4)

    def test_decision_variant_count(self) -> None:
        self.assertEqual(len(mod.TRUST_DECISION_VARIANTS), 3)


if __name__ == "__main__":
    unittest.main()
